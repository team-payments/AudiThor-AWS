# collectors/security_hub.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def check_security_hub_status_in_regions(session, regions):
    """
    Verifica el estado de Security Hub en cada región y, si está activo,
    OBTIENE EL RESUMEN DE CUMPLIMIENTO para cada estándar habilitado.
    """
    results = []
    for region in regions:
        # La estructura de datos que devolvemos ahora es más rica
        region_status = {
            "Region": region, 
            "SecurityHubEnabled": False,
            "ComplianceSummaries": [] # <-- NUEVO CAMPO para los datos de cumplimiento
        }
        
        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub() # Comprobamos si está activo
            
            # Si la línea anterior no falla, Security Hub está habilitado
            region_status["SecurityHubEnabled"] = True
            
            # 1. Obtenemos los estándares habilitados (CIS, PCI, etc.)
            enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])
            
            for standard in enabled_standards:
                standard_arn = standard.get('StandardsSubscriptionArn')
                standard_name_raw = standard.get('StandardsArn', 'N/A').split('/standard/')[-1].replace('-', ' ').title()

                # 2. Para cada estándar, obtenemos el estado de todos sus controles
                controls = securityhub_client.describe_standards_controls(
                    StandardsSubscriptionArn=standard_arn
                ).get('Controls', [])

                if not controls:
                    continue

                # 3. Calculamos el resumen de cumplimiento
                passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                total_controls = len(controls)
                compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

                # 4. Guardamos el resumen del estándar en nuestro nuevo campo
                region_status["ComplianceSummaries"].append({
                    "standardName": standard_name_raw,
                    "compliancePercentage": round(compliance_percentage, 2),
                    "passedCount": passed_count,
                    "totalControls": total_controls,
                })

        except ClientError:
            # Esto ocurre si SH no está activo, lo cual es normal.
            pass
            
        results.append(region_status)
        
    return results

def get_and_filter_security_hub_findings(session, region_statuses):
    all_findings, iam_findings, exposure_findings, waf_findings, cloudtrail_findings, cloudwatch_findings, inspector_findings = [], [], [], [], [], [], []
    active_regions = [r['Region'] for r in region_statuses if r['SecurityHubEnabled']]
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            pages = paginator.paginate(Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]})
            for page in pages: all_findings.extend(page['Findings'])
        except ClientError: pass
    
    iam_findings = [f for f in all_findings if 'IAM' in f.get('Compliance', {}).get('SecurityControlId', '')]
    exposure_keywords = ['public', 'internet-facing', 'exposed', 'open', '0.0.0.0/0', 's3', 'ec2', 'elb', 'rds', 'lambda', 'api gateway', 'cloudfront']
    exposure_findings = [f for f in all_findings if any(keyword in f.get('Title', '').lower() for keyword in exposure_keywords)]
    waf_findings = [f for f in all_findings if 'WAF' in f.get('Compliance', {}).get('SecurityControlId', '')]
    cloudtrail_findings = [f for f in all_findings if 'cloudtrail' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    cloudwatch_findings = [f for f in all_findings if 'cloudwatch' in f.get('Compliance', {}).get('SecurityControlId', '').lower()]
    
    # Lista de IDs de control de Security Hub específicos para la configuración de Inspector
    # Basado en: https://docs.aws.amazon.com/es_es/securityhub/latest/userguide/inspector-controls.html
    inspector_control_ids = [
        "Inspector.1",
        "Inspector.2",
        "Inspector.3",
        "Inspector.4",
        "Inspector.5",
        "Inspector.6"
    ]
    inspector_findings = [
        f for f in all_findings 
        if f.get('Compliance', {}).get('SecurityControlId') in inspector_control_ids
    ]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    for findings_list in [iam_findings, exposure_findings, waf_findings, cloudtrail_findings, cloudwatch_findings, inspector_findings]:
        findings_list.sort(key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99))
    
    return { "iamFindings": iam_findings, "exposureFindings": exposure_findings, "wafFindings": waf_findings, "cloudtrailFindings": cloudtrail_findings, "cloudwatchFindings": cloudwatch_findings, "inspectorFindings": inspector_findings }

def calculate_compliance_from_findings(all_findings):
    """
    Calcula el estado de cumplimiento de cada estándar basándose en una lista de findings.
    Esta es la forma correcta de obtener el estado PASSED/FAILED.
    """
    compliance_data = {}
    
    for finding in all_findings:
        # Nos interesan solo los findings que vienen de un estándar de seguridad
        if 'Compliance' not in finding or not finding['Compliance'].get('SecurityControlId'):
            continue

        # Extraemos el nombre del estándar y el estado del control del finding
        standard_arn = finding.get('ProductFields', {}).get('StandardsArn', 'N/A')
        control_status = finding.get('Compliance', {}).get('Status', 'UNKNOWN')

        if standard_arn not in compliance_data:
            compliance_data[standard_arn] = {'passed': 0, 'failed': 0, 'other': 0}

        if control_status == 'PASSED':
            compliance_data[standard_arn]['passed'] += 1
        elif control_status == 'FAILED':
            compliance_data[standard_arn]['failed'] += 1
        else:
            compliance_data[standard_arn]['other'] += 1

    # Procesamos los conteos para devolver un resumen con porcentajes
    summary_list = []
    for arn, counts in compliance_data.items():
        total_controls_found = counts['passed'] + counts['failed']
        if total_controls_found > 0:
            percentage = round((counts['passed'] / total_controls_found) * 100, 2)
            
            # Extraemos un nombre legible del ARN
            standard_name = arn.split('/standard/')[-1].replace('-', ' ').title() if '/standard/' in arn else arn

            summary_list.append({
                "standardArn": arn,
                "standardName": standard_name,
                "compliancePercentage": percentage,
                "passedCount": counts['passed'],
                "failedCount": counts['failed'],
                "otherCount": counts['other'],
                "totalControls": total_controls_found # Usamos el total de findings (passed+failed)
            })
            
    return summary_list