import os
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError

# --- Azure Credentials ---
# Set these in your terminal before running the script:
# export AZURE_TENANT_ID="your_tenant_id"
# export AZURE_CLIENT_ID="your_client_id"
# export AZURE_CLIENT_SECRET="your_client_secret"
# export AZURE_SUBSCRIPTION_ID="your_subscription_id"

tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

# --- Initialize Azure Clients ---
# Create a credential object for authentication
credentials = ClientSecretCredential(tenant_id, client_id, client_secret)

# Create the Network Management client
network_client = NetworkManagementClient(credentials, subscription_id)


def block_ips_in_nsg(resource_group_name, nsg_name, ip_addresses, start_priority=300):
    """
    Blocks a list of IP addresses by creating new inbound security rules in an NSG.

    Args:
        resource_group_name (str): The name of the resource group containing the NSG.
        nsg_name (str): The name of the Network Security Group to update.
        ip_addresses (list): A list of IP address strings to block.
        start_priority (int): The starting priority for the new rules. Must be between 100 and 4096.
                              Each new rule will have a priority incremented from this value.
    """
    print(f"--- Starting IP block process for NSG '{nsg_name}' ---")

    for i, ip_address in enumerate(ip_addresses):
        # Each rule needs a unique priority. We'll start at `start_priority` and increment.
        current_priority = start_priority + i

        if current_priority > 4096:
            print(
                f"Error: Rule priority {current_priority} exceeds the maximum of 4096. Stopping."
            )
            break

        # Create a unique, valid rule name
        rule_name = f"Block-IP-Auto-{ip_address.replace('.', '-')}"

        # Define the security rule object
        security_rule_parameters = {
            "protocol": "*",  # Corrected parameter name from 'protocols'
            "source_address_prefix": ip_address,
            "destination_address_prefix": "*",
            "source_port_range": "*",
            "destination_port_range": "*",
            "access": "Deny",
            "priority": current_priority,
            "direction": "Inbound",
            "description": f"Automated block for flagged IP {ip_address}",
        }

        try:
            print(
                f"Attempting to create rule '{rule_name}' to block {ip_address} with priority {current_priority}..."
            )

            # Asynchronously create or update the security rule
            poller = network_client.security_rules.begin_create_or_update(
                resource_group_name, nsg_name, rule_name, security_rule_parameters
            )

            # Wait for the operation to complete
            poller.result()

            print(f"Successfully blocked IP {ip_address} in NSG '{nsg_name}'.")

        except HttpResponseError as e:
            # Handle potential errors, e.g., if a rule with that priority already exists
            print(f"Error blocking IP {ip_address}: {e.message}")
        except Exception as e:
            print(f"An unexpected error occurred for IP {ip_address}: {e}")

    print("--- IP block process finished. ---")


# List provided by ML bot's output
flagged_bot_ips = ["203.0.113.1", "198.51.100.5", "192.0.2.10"]

# Azure resource details
resource_group = "myResourceGroup"
network_security_group = "myNetworkSecurityGroup"

block_ips_in_nsg(resource_group, network_security_group, flagged_bot_ips)
