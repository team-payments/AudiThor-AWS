# collectors/guardduty.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_guardduty_data(session):
    all_regions = get_all_aws_regions(session)
    status_by_region = []
    all_findings_raw = []

    for region in all_regions:
        try:
            gd_client = session.client("guardduty", region_name=region)
            detectors = gd_client.list_detectors()
            
            if not detectors.get("DetectorIds"):
                # --- MODIFICADO: Añadimos las nuevas claves también al estado por defecto ---
                status_by_region.append({"Region": region, "Status": "Not Enabled", "S3 Logs": "-", "Kubernetes Logs": "-", "EC2 Malware Protection": "-", "EKS Malware Protection": "-"})
                continue

            detector_id = detectors["DetectorIds"][0]
            detector_details = gd_client.get_detector(DetectorId=detector_id)
            
            features = {f["Name"]: "Enabled" if f["Status"] == "ENABLED" else "Disabled" for f in detector_details.get("Features", [])}

            status_by_region.append({
                "Region": region,
                "Status": "Enabled" if detector_details.get("Status") == "ENABLED" else "Suspended",
                "S3 Logs": features.get("S3_DATA_EVENTS", "N/A"),
                "Kubernetes Logs": features.get("KUBERNETES_AUDIT_LOGS", "N/A"),
                "EC2 Malware Protection": features.get("MALWARE_PROTECTION", "N/A"),
                "EKS Malware Protection": features.get("EKS_RUNTIME_MONITORING", "N/A"),
            })

            if detector_details.get("Status") == "ENABLED":
                paginator = gd_client.get_paginator('list_findings')
                pages = paginator.paginate(DetectorId=detector_id, FindingCriteria={'Criterion': {'service.archived': {'Eq': ['false']}}})
                for page in pages:
                    if page.get("FindingIds"):
                        findings_details = gd_client.get_findings(DetectorId=detector_id, FindingIds=page["FindingIds"])
                        all_findings_raw.extend(findings_details.get("Findings", []))
        except ClientError as e:
            if "endpoint" in str(e) or "OptInRequired" in str(e) or "Location" in str(e): continue
            status_by_region.append({"Region": region, "Status": f"Error ({type(e).__name__})", "S3 Logs": "-", "Kubernetes Logs": "-", "EC2 Malware Protection": "-", "EKS Malware Protection": "-"})

    # El resto de la función para procesar findings no cambia
    processed_findings = []
    for f in all_findings_raw:
        severity_map = {1: "LOW", 2: "LOW", 3: "LOW", 4: "MEDIUM", 5: "MEDIUM", 6: "MEDIUM", 7: "HIGH", 8: "HIGH", 9: "CRITICAL", 10: "CRITICAL"}
        severity_score = int(f.get("Severity", 0))
        resource = f.get("Resource", {})
        resource_type = resource.get("ResourceType", "N/A")
        resource_details_str = "N/A"
        if resource_type == "AccessKey":
            details = resource.get('AccessKeyDetails', {})
            resource_details_str = f"{details.get('UserType', 'N/A')}: {details.get('UserName', 'N/A')}"
        elif resource_type == "Instance":
             details = resource.get('InstanceDetails', {})
             resource_details_str = f"ID: {details.get('InstanceId', 'N/A')}"
        elif resource_type == 'EksCluster':
            details = resource.get('EksClusterDetails', {})
            resource_details_str = f"Cluster: {details.get('Name', 'N/A')}"
        elif resource_type == 'S3Bucket':
            details = resource.get('S3BucketDetails', [])
            if details: resource_details_str = f"Bucket: {details[0].get('Name', 'N/A')}"
        processed_findings.append({
            "SeverityScore": severity_score, "SeverityLabel": severity_map.get(severity_score, "INFORMATIONAL"),
            "Region": f.get("Region", "N/A"), "Type": f.get("Type", "N/A"),
            "Resource": f"{resource_type} - {resource_details_str}", "LastSeen": f.get("UpdatedAt", "N/A").split("T")[0],
            "Title": f.get("Title", "N/A")
        })
    processed_findings.sort(key=lambda x: x["SeverityScore"], reverse=True)
    
    return {"status": status_by_region, "findings": processed_findings}
