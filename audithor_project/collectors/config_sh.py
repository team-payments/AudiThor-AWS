# collectors/config_sh.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def sh_check_regional_services(session, regions):
    """
    MODIFICADO: Ahora también devuelve un mapa para relacionar cada control con su estándar.
    """
    results = []
    # Este mapa nos ayudará a saber a qué estándar pertenece cada control (ej: 'ACM.1' -> 'arn:aws:.../aws-foundational-security-best-practices/v/1.0.0')
    control_to_standard_map = {}

    for region in regions:
        region_status = {
            "Region": region, "ConfigEnabled": False, "SecurityHubEnabled": False,
            "EnabledStandards": [], "EnabledConformancePacks": [],
            "ComplianceSummaries": []
        }
        try:
            config_client = session.client("config", region_name=region)
            # ... (el resto del chequeo de Config no cambia)
            status = config_client.describe_configuration_recorder_status()
            if status.get("ConfigurationRecordersStatus") and status["ConfigurationRecordersStatus"][0].get("recording"):
                region_status["ConfigEnabled"] = True
                try:
                    cp_response = config_client.describe_conformance_packs()
                    for cp in cp_response.get('ConformancePackDetails', []):
                        region_status["EnabledConformancePacks"].append(cp.get('ConformancePackName'))
                except ClientError: pass
        except ClientError: pass
            
        try:
            securityhub_client = session.client("securityhub", region_name=region)
            securityhub_client.describe_hub()
            region_status["SecurityHubEnabled"] = True
            
            try:
                standards_response = securityhub_client.get_enabled_standards()
                for standard in standards_response.get('StandardsSubscriptions', []):
                    standard_arn_full = standard.get('StandardsArn', 'unknown')
                    region_status["EnabledStandards"].append(standard_arn_full)
                    
                    standard_subscription_arn = standard.get('StandardsSubscriptionArn')
                    controls = securityhub_client.describe_standards_controls(
                        StandardsSubscriptionArn=standard_subscription_arn
                    ).get('Controls', [])

                    if not controls: continue

                    # --- Lógica de mapeo añadida ---
                    for control in controls:
                        control_id = control.get('ControlId')
                        if control_id:
                            control_to_standard_map[control_id] = standard_arn_full
                    
                    # El cálculo de contadores aquí ya no es necesario para el gráfico, 
                    # pero lo dejamos por si se usa en otro lado.
                    passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
                    region_status["ComplianceSummaries"].append({
                        "standardArn": standard_arn_full,
                        "standardName": standard_arn_full.split('/standard/')[-1].replace('-', ' ').title(),
                        "totalControls": len(controls),
                        "passedCount": passed_count
                    })
            except ClientError: pass
        except ClientError: pass
            
        results.append(region_status)
    # Devolvemos tanto los resultados como el mapa de controles
    return results, control_to_standard_map

def collect_config_sh_status_only(session):
    """
    FUNCIÓN RÁPIDA: Obtiene solo el estado de activación de Config y SH por región.
    """
    regions = get_all_aws_regions(session)
    # --- CORRECCIÓN CLAVE AQUÍ ---
    # Desempaquetamos la tupla para quedarnos solo con la lista de resultados.
    service_status_list, _ = sh_check_regional_services(session, regions)
    return {
        "service_status": service_status_list
    }

def get_compliance_for_region(securityhub_client):
    """
    Recibe un cliente de Security Hub ya inicializado para una región activa
    y devuelve el resumen de cumplimiento para sus estándares.
    """
    compliance_summary = []
    try:
        enabled_standards = securityhub_client.get_enabled_standards().get('StandardsSubscriptions', [])
        for standard in enabled_standards:
            standard_arn = standard.get('StandardsSubscriptionArn')
            standard_name_raw = standard.get('StandardsArn', 'N/A').split('/standard/')[-1].replace('-', ' ').title()

            controls = securityhub_client.describe_standards_controls(
                StandardsSubscriptionArn=standard_arn
            ).get('Controls', [])

            if not controls:
                continue

            passed_count = sum(1 for c in controls if c.get('ControlStatus') == 'PASSED')
            total_controls = len(controls)
            compliance_percentage = (passed_count / total_controls * 100) if total_controls > 0 else 100

            compliance_summary.append({
                "standardName": standard_name_raw,
                "compliancePercentage": round(compliance_percentage, 2),
                "passedCount": passed_count,
                "totalControls": total_controls,
            })
    except Exception as e:
        print(f"    [!] Could not retrieve the compliance summary: {e}")

    return compliance_summary

def sh_get_security_hub_findings(session, service_status):
    """
    Obtiene todos los findings ACTIVOS de Security Hub de todas las regiones.
    Adaptado de securityhub.py para la API web (sin prints/tqdm).
    """
    all_findings = []
    active_regions = [r['Region'] for r in service_status if r['SecurityHubEnabled']]
    
    for region_name in active_regions:
        try:
            sh_client = session.client("securityhub", region_name=region_name)
            paginator = sh_client.get_paginator('get_findings')
            pages = paginator.paginate(Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]})
            for page in pages:
                all_findings.extend(page['Findings'])
        except ClientError:
            pass # Si falla (ej. permisos), se omite la región.
            
    return all_findings

def collect_config_sh_data(session):
    """
    MODIFICADO: Reconstruye el resumen de cumplimiento basándose en los hallazgos
    para asegurar consistencia entre las pestañas.
    """
    regions = get_all_aws_regions(session)
    service_status_results, control_map = sh_check_regional_services(session, regions)
    findings = sh_get_security_hub_findings(session, service_status_results)
    
    compliance_summary_map = {}
    for region_data in service_status_results:
        for summary in region_data.get("ComplianceSummaries", []):
            arn = summary['standardArn']
            if arn not in compliance_summary_map:
                compliance_summary_map[arn] = {
                    "standardArn": arn,
                    "standardName": summary['standardName'],
                    "totalControls": summary.get('totalControls', 0),
                    "passedCount": 0, "failedCount": 0, "warningCount": 0, 
                    "notAvailableCount": 0, "otherCount": 0
                }

    for finding in findings:
        status = finding.get('Compliance', {}).get('Status')
        control_id = finding.get('Compliance', {}).get('SecurityControlId')
        
        standard_arn = control_map.get(control_id)

        if standard_arn and standard_arn in compliance_summary_map:
            if status == 'PASSED':
                compliance_summary_map[standard_arn]['passedCount'] += 1
            elif status == 'FAILED':
                compliance_summary_map[standard_arn]['failedCount'] += 1
            elif status == 'WARNING':
                compliance_summary_map[standard_arn]['warningCount'] += 1
            elif status == 'NOT_AVAILABLE':
                compliance_summary_map[standard_arn]['notAvailableCount'] += 1

    final_summary = []
    for arn, data in compliance_summary_map.items():
        counted = data['passedCount'] + data['failedCount'] + data['warningCount'] + data['notAvailableCount']
        
        # Nos aseguramos de que el resultado de la resta nunca sea menor que 0.
        data['otherCount'] = max(0, data['totalControls'] - counted)

        final_summary.append(data)

    # Enriquecer cada finding con el ARN del estándar correspondiente usando el mapa.
    # Esto asegura que el frontend siempre tenga el ARN para poder filtrar.
    for finding in findings:
        control_id = finding.get('Compliance', {}).get('SecurityControlId')
        if control_id in control_map:
            standard_arn = control_map[control_id]
            # Asegurarse de que ProductFields existe antes de añadir la clave
            if 'ProductFields' not in finding:
                finding['ProductFields'] = {}
            # Añadimos o sobreescribimos el StandardsArn para asegurar que esté presente
            finding['ProductFields']['StandardsArn'] = standard_arn

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    findings.sort(key=lambda x: severity_order.get(x.get('Severity', {}).get('Label', 'INFORMATIONAL'), 99))

    return {
        "service_status": service_status_results,
        "findings": findings,
        "compliance_summary": final_summary
    }
