# collectors/acm.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_acm_data_web(session):
    all_regions = session.get_available_regions('acm')
    result_certificates = []

    for region in all_regions:
        try:
            acm_client = session.client("acm", region_name=region)
            paginator_certs = acm_client.get_paginator('list_certificates')
            
            for page in paginator_certs.paginate():
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    try:
                        cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
                        cert_details['Region'] = region
                        if 'IssuedAt' in cert_details:
                            cert_details['IssuedAt'] = cert_details['IssuedAt'].isoformat()
                        if 'NotAfter' in cert_details:
                            cert_details['NotAfter'] = cert_details['NotAfter'].isoformat()
                        result_certificates.append(cert_details)
                    except ClientError as e:
                        if "OptInRequired" in str(e) or "endpoint" in str(e):
                            continue
                        print(f"Warning: Could not retrieve details for certificate {cert_arn} in {region}: {e}")
        except ClientError as e:
            if "OptInRequired" in str(e) or "endpoint" in str(e) or "SignatureDoesNotMatch" in str(e): 
                continue
            print(f"Notice: ACM service not available or no permissions in {region}: {e}")

    result_certificates.sort(key=lambda x: (x.get('Region', ''), x.get('DomainName', '')))
    
    return {"certificates": result_certificates}

