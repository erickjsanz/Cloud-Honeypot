# Building a SOC + Honeynet in Azure (Live Cyber Attacks)
![Cloud Honey + SOC](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/39a0fb9b-4249-4352-8e7c-d5a0658f52e6)

## Introduction

In this project, I constructed a mini honeynet within the Azure platform to capture and analyze security logs from various sources. These logs were then consolidated within a Log Analytics workspace. Microsoft Sentinel was utilized to leverage these logs, enabling the development of attack maps, creation of alert triggers, and generation of incidents.

The project was conducted over two distinct 24-hour phases:

- Initial Measurement Phase: Azure Sentinel monitored the metrics of an insecure environment for 24 hours.
- Post-Security Controls Phase: Security controls were implemented to fortify the virtual environment, followed by another 24-hour metric measurement period.

The metrics analyzed were:
- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Technologies, Azure Components, and Regulations Employed
- Azure Virtual Network (VNet)
- Azure Network Security Groups (NSG)
- Virtual Machines: 2 Windows VMs, 1 Linux VM
- Log Analytics Workspace with Kusto Query Language (KQL) Queries
- Azure Key Vault for Secure Secrets Management
- Azure Storage Account for Data Storage
- Microsoft Sentinel for Security Information and Event Management (SIEM)
- Microsoft Defender for Cloud to Protect Cloud Resources
- Windows Remote Desktop (RDP) for Remote Access
- Command Line Interface (CLI) for System Management
- PowerShell for Automation and Configuration Management
- [NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) for Security Controls
- [NIST SP 800-61 Revision 2](https://www.nist.gov/privacy-framework/nist-sp-800-61) for Incident Handling Guidance

## Architecture Before Hardening / Security Controls
![Cloud Honey + SOC(3)](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/8b79dd7c-e7e0-4b8d-876d-97acd4a1e6fb)

In the "BEFORE" stage of this project, I deployed a virtual environment exposed to the public Internet to attract and analyze threat actors' attack patterns. This environment included a Windows virtual machine hosting a SQL database and a Linux server, both configured with "Allow All" network security groups (NSGs) settings. Additionally, a storage account and key vault were deployed with public endpoints to further entice attackers. Microsoft Sentinel was utilized to monitor the unsecured environment, with logs aggregated by the Log Analytics workspace.

## Architecture After Hardening / Security Controls
![Cloud Honey + SOC(4)](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/70816bf5-78aa-4c6d-b7cd-5f9267ec4f10)

In the "AFTER" stage of this project, the environment was hardened, and security controls were implemented to comply with NIST SP 800-53 Rev4 SC-7(3) Access Points. The following hardening tactics were applied:

- Network Security Groups (NSGs): Hardened NSGs by blocking all inbound and outbound traffic, except for designated public IP addresses requiring access. This ensured that only authorized traffic from trusted sources could access the virtual machines.
- Built-in Firewalls: Configured Azure's built-in firewalls on the virtual machines to restrict unauthorized access and protect resources from malicious connections. This involved fine-tuning firewall rules based on the service and responsibilities of each VM, mitigating the attack surface.
- Private Endpoints: Replaced public endpoints with private endpoints for Azure Key Vault and Storage Containers. This limited access to the virtual network, ensuring sensitive resources were not exposed to the public Internet.

## Attack Maps Before Hardening / Security Controls
- This attack map illustrates the traffic allowed by a Network Security Group (NSG) configured to allow all inbound traffic. The unrestricted inbound traffic setting provides an open invitation to potential threat actors.
![nsg-malicious-allowed-in](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/9fd9965f-34ff-4d79-8abc-2b9d28dffd76)
- This attack map demonstrates all the attempts by threat actors to access the Linux virtual machine via SSH (Secure Shell). The unrestricted inbound traffic setting for SSH on the Network Security Group (NSG).
![linux-ssh-auth-fail](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/765f318d-2b22-424b-8b61-91539bd4d276)
- This attack map illustrates all the attempts by threat actors to access the Windows virtual machine via RDP (Remote Desktop Protocol). The unrestricted inbound traffic setting for RDP on the Network Security Group (NSG).
![windows-rdp-auth-fail](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/f8348cf8-03eb-4072-8db1-3524ba1bd8ea)

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
- Start Time 2024-06-06 11:43
- Stop Time 2024-06-07 11:43

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 17533
| Syslog                   | 4981
| SecurityAlert            | 0
| SecurityIncident         | 137
| AzureNetworkAnalytics_CL | 2290

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
- Start Time 2024-06-13 22:22
- Stop Time	2024-06-14 22:22

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 4329
| Syslog                   | 1
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

This project has underscored the critical importance of security, and I thoroughly enjoyed creating it. Proper security controls and configurations are essential to protect resources. The before and after metrics clearly highlight the stark contrast between an insecure and a secure environment, with the attack map data illustrating these changes vividly. Implementing firewall rules, private endpoints, and restricting public internet access are crucial measures to prevent disastrous consequences caused by threat actors and unauthorized access to critical assets and resources.

In conclusion, I set up a compact yet effective honeynet using Microsoft Azure's robust cloud infrastructure. Microsoft Sentinel was utilized to trigger alerts and generate incidents based on logs ingested from the watch lists. Baseline metrics were recorded in the unprotected environment before the implementation of any security controls. Following this, a range of security measures were enforced to fortify the network against potential threats. After implementing these controls, another set of measurements was taken. The comparison of pre- and post-implementation metrics demonstrated a significant reduction in security events and incidents, highlighting the effectiveness of the enforced security controls.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
