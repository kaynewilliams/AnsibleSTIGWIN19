Running Ansible Playbook for Windows STIG Compliance (BETA TEST ON STANDALONE NODE)

Observations:
Remote SCC scanning only works when target systems are in the same AD domain as the client. This is why my lab scan attempt to the EC2 instance was unsuccessful. This is explained in: https://www.youtube.com/watch?v=asutYWy57Yc (NAVWAR's SCAP Compliance Checker Tutorial 1: Introduction to SCAP and SCC)

PowerShell commands used to setup WinRM on AWS EC2 test target (We will adjust to our own requirements for our network):
# Enable PowerShell remoting
Enable-PSRemoting -Force

# Set WinRM service startup type to automatic
Set-Service WinRM -StartupType 'Automatic'

# Configure WinRM Service
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
Set-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -Value $true
Set-Item -Path 'WSMan:\localhost\Service\Auth\CredSSP' -Value $true

# Create a self-signed certificate and set up an HTTPS listener
$cert = New-SelfSignedCertificate -DnsName $(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname) -CertStoreLocation "cert:\LocalMachine\My"
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$(Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/public-hostname)`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

# Create a firewall rule to allow WinRM HTTPS inbound
New-NetFirewallRule -DisplayName "Allow WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow

# Configure TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Set LocalAccountTokenFilterPolicy
New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force

# Set Execution Policy to Unrestricted
Set-ExecutionPolicy Unrestricted -Force

# Restart the WinRM service
Restart-Service WinRM

# List the WinRM listeners
winrm enumerate winrm/config/Listener


![Playbook Execute](https://github.com/kaynewilliams/AnsibleSTIGWIN19/assets/122909338/dee6ddfd-4c6e-4e8d-9e50-8f9520c1877f)


Process for running the playbook from a CENTOS 8 VM running in VMWARE Workstation:
1. Perform scan using the SCC tool provided at https://public.cyber.mil/stigs/scap/. The score for a base Windows Server 2019 Base image was 36% compliant. 
2. Install Python on Ansible control node (dnf install python)
3. Install Ansible on Ansible control node (pip3.11 install ansible)
4. Install WinRM on Ansible control node (pip3.11 install pywinrm)
5. Install Git (dnf install git)
6. Clone Git repository to push MindPoint/Ansible-Lockdown content to Ansible control node. (git clone https://github.com/ansible-lockdown/Windows-2019-STIG)
7. Create Ansible directory to build the .ini (inventory) file in. Windows uses .ini format to store target hosts.
8. Install dependencies listed on the Git repository ReadME.md
   - passlib (or python2-passlib, if using python2)
   - python-lxml
   - python-xmltodict
   - python-jmespath
9. Final command to run the playbook: ansible-playbook -i /etc/ansible/window.ini ./site.yml (ran out of the cloned repository directory)
    
![Playbook Results](https://github.com/kaynewilliams/AnsibleSTIGWIN19/assets/122909338/713b852d-3ead-444c-b78e-ad1d55014605)

![SCC Report Score After Default MindPoint Playbook Deployment](https://github.com/kaynewilliams/AnsibleSTIGWIN19/assets/122909338/fe53a248-d94d-47c1-8521-3a9c0d4654b8)

