# collectors/connectivity.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa

def collect_connectivity_data(session):
    """
    Recopila información sobre VPC Peering, Transit Gateway, VPNs y VPC Endpoints.
    """
    regions = get_all_aws_regions(session)
    result = {
        "peering_connections": [],
        "tgw_attachments": [],
        "vpn_connections": [],
        "vpc_endpoints": []
    }

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            
            # 1. VPC Peering Connections (solo activas)
            peering_paginator = ec2_client.get_paginator('describe_vpc_peering_connections')
            for page in peering_paginator.paginate(Filters=[{'Name': 'status-code', 'Values': ['active']}]):
                for pcx in page.get("VpcPeeringConnections", []):
                    result["peering_connections"].append({
                        "Region": region,
                        "ConnectionId": pcx.get("VpcPeeringConnectionId"),
                        "RequesterVpc": pcx.get("RequesterVpcInfo", {}),
                        "AccepterVpc": pcx.get("AccepterVpcInfo", {})
                    })

            # 2. Transit Gateway VPC Attachments (solo disponibles)
            tgw_paginator = ec2_client.get_paginator('describe_transit_gateway_attachments')
            for page in tgw_paginator.paginate(Filters=[{'Name': 'resource-type', 'Values': ['vpc']}, {'Name': 'state', 'Values': ['available']}]):
                for tgw_attachment in page.get("TransitGatewayAttachments", []):
                    result["tgw_attachments"].append({
                        "Region": region,
                        "AttachmentId": tgw_attachment.get("TransitGatewayAttachmentId"),
                        "TransitGatewayId": tgw_attachment.get("TransitGatewayId"),
                        "VpcId": tgw_attachment.get("ResourceId"),
                        "VpcOwnerId": tgw_attachment.get("ResourceOwnerId")
                    })

            # 3. Site-to-Site VPN Connections (solo disponibles)
            vpns = ec2_client.describe_vpn_connections(Filters=[{'Name': 'state', 'Values': ['available']}])
            for vpn in vpns.get("VpnConnections", []):
                result["vpn_connections"].append({
                    "Region": region,
                    "VpnConnectionId": vpn.get("VpnConnectionId"),
                    "CustomerGatewayId": vpn.get("CustomerGatewayId"),
                    "TransitGatewayId": vpn.get("TransitGatewayId", "N/A"),
                    "State": vpn.get("State")
                })

            # 4. VPC Endpoints
            endpoint_paginator = ec2_client.get_paginator('describe_vpc_endpoints')
            for page in endpoint_paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                     result["vpc_endpoints"].append({
                        "Region": region,
                        "VpcEndpointId": endpoint.get("VpcEndpointId"),
                        "VpcId": endpoint.get("VpcId"),
                        "ServiceName": endpoint.get("ServiceName"),
                        "EndpointType": endpoint.get("VpcEndpointType"),
                        "State": endpoint.get("State")
                    })

        except ClientError as e:
            if e.response['Error']['Code'] in ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']:
                continue
        except Exception:
            continue
            
    return result

