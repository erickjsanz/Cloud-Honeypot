# Building a SOC + Honeynet in Azure (Live Cyber Attacks)
![Cloud Honey + SOC](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/39a0fb9b-4249-4352-8e7c-d5a0658f52e6)

## Introduction

In this project, I constructed a mini honeynet within the Azure platform to capture and analyze security logs from various sources. These logs were then consolidated within a Log Analytics workspace. Microsoft Sentinel was utilized to leverage these logs, enabling the development of attack maps, creation of alert triggers, and generation of incidents.

The project was conducted over two distinct 24-hour phases:

1)Initial Measurement Phase: Azure Sentinel monitored the metrics of an insecure environment for 24 hours.
2)Post-Security Controls Phase: Security controls were implemented to fortify the virtual environment, followed by another 24-hour metric measurement period.

The metrics analyzed were:
- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![Cloud Honey + SOC(3)](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/8b79dd7c-e7e0-4b8d-876d-97acd4a1e6fb)
## Architecture After Hardening / Security Controls
![Cloud Honey + SOC(4)](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/70816bf5-78aa-4c6d-b7cd-5f9267ec4f10)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls
![nsg-malicious-allowed-in](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/9fd9965f-34ff-4d79-8abc-2b9d28dffd76)
![linux-ssh-auth-fail](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/765f318d-2b22-424b-8b61-91539bd4d276)
![windows-rdp-auth-fail](https://github.com/erickjsanz/Cloud-Honeypot/assets/7691426/f8348cf8-03eb-4072-8db1-3524ba1bd8ea)

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-03-15 17:04:29
Stop Time 2023-03-16 17:04:29

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
Start Time 2023-03-18 15:37
Stop Time	2023-03-19 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 4329
| Syslog                   | 1
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
