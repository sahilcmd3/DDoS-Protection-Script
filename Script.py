import os
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

# Azure credentials
tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

# Create a credential object
credentials = ClientSecretCredential(tenant_id, client_id, client_secret)

# Create the Network Management client
network_client = NetworkManagementClient(credentials, subscription_id)

def block_ip_in_nsg(resource_group_name, nsg_name, ip_address):
    rule_name = f"block-ip-{ip_address.replace('.', '-')}"
    
    security_rule = {
        "name": rule_name,
        "protocols": ["*"],
        "source_address_prefix": ip_address,
        "destination_address_prefix": "*",
        "access": "Deny",
        "priority": 100,
        "direction": "Inbound",
        "description": f"Block traffic from IP {ip_address}"
    }

    network_client.security_rules.begin_create_or_update(
        resource_group_name,
        nsg_name,
        rule_name,
        security_rule
    ).result()

    print(f"Blocked IP {ip_address} in NSG {nsg_name}.")

# Usage example
block_ip_in_nsg('myResourceGroup', 'myNetworkSecurityGroup', '203.0.113.1')
