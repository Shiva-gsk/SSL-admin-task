# SSL Admin Task Documentation
My documentation on SSL-admin Task basically has the following steps. you can use specific Links to get to the desired section.

1. [Initial Setup](#stage-1---intial-setup)
2. [Enhanced Security](#enhanced-security)
3. [Firewall and Network security](#firewall-and-network-security)
4. [User and Permission Management](#user-and-permission-management)
5. [Web Server Deployment and Secure Configuration](#web-server-deployment-and-secure-configuration)
<!-- 3. []() -->


### *Date: 14th May, 2025*
## Stage 1 - Intial Setup 
This Stage required me to rent a Cloud VM on Azure or some similar platform.
I was actually new to using such platforms, so it took me some time to understand about them.

I basically signup to Azure Platform and I got about $100 free credits that can be used for over 365 days. I created a static IP resource and a VM using Static IP that I created. Though an easy setup, this took me some time as I was to new to such platform.

Now after setting up VM our first task to enable unattended upgrades for security

Following Commands are used to setup unattended upgrades making sure system always receives latest security upgrades.

```
sudo apt update
sudo apt install unattended-upgrades
```
<!-- sudo dpkg-reconfigure --priority=low unattended-upgrades -->
After installing packages we need to make some little changes to config files

```
sudo vim /etc/apt/apt.conf.d/50unattended-upgrades
```
We need to make sure that `` "${distro_id}:${distro_codename}-security"`` is uncommented.

Also we need to make sure daily updates are enabled, so that updates are run automatically on a schedule. For this make sure that

```
sudo nano /etc/apt/apt.conf.d/20auto-upgrades 
```

this file has below fields.
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

And there we go..

The intial setup is finally done 😮‍💨


## Enhanced Security

Usually we use login credentials to get into ssh of some remote pc. But it isn't that much secure. (Brute force can be done basically..)

Here we are implementing a secure way to ssh using public-private key a cryptographic way to secure login.

I got to know concepts regarding this while setting up ssh key to my github, so the stage went quite smoothly..

*Public-Private key is a mechanism where a unique signature made by Private key which can be verified by respective public key.*

- Private key should be kept secret, and public key is used to verify the signature to permit access.

In the context of SSH here we store our private key on our device and while using SSH to get access to remote pc's shell.


### Enable Public-Private Key Auth

1. First we need to create a public-private key pair. this is usually done on our local pc. We can use command ``ssh-keygen`` to create one for us.

2. After Creating a public-private key we need to copy the public key which is stored as .pub file and we need to go to our VM and add it. For this we need to run following commands

    ```
    mkdir -p ~/.ssh
    vim ~/.ssh/authorized_keys
    ```
    Here we need to paste our public key in a single line.

3. Finally now we can ssh using our stored private key on our device. We can just type the following command to establish a connection for us.
 
    ```
    ssh -i /path_to_private_key username@remote_host_ip
    ```
    This basically verifies the private key on our local pc using saved public key on VM and gives access to shell, kinda more secure than usual login credentials..
    
*After these steps we need to restart our SSH service using systemctl utility.
### Disable Root Login

For this we need to go to SSH daemon config file which is located at ``/etc/ssh/sshd_config`` and change ``PermitRootLogin`` to ``no``.

This basically prevents brute force password attacks on root as its basically well-known username.

### Disable Password Authentication

Similar to root login we need to change the ``PasswordAuthentication`` to ``no`` in the same SSH daemon config file.

But I found an issue with it as i was still able to access SSH through password. After searching through config files found that a file in ``/etc/ssh/sshd_config.d/50-cloud-init.conf`` has ``PasswordAuthentication`` set to ``yes`` and the file is included in sshd_config file, which makes me still access SSH using password. 

To completely disable password access to SSH we need to change ``PasswordAuthentication`` in that file to ``no``.

```
sudo vim /etc/ssh/sshd_config.d/50-cloud-init.conf
```

and change 
```
PasswordAuthentication no
```

### *Date: 15th May, 2025*

### Restricting SSH access to specific users 

When i researched about this i came to know that there are actually different ways, but yeah using firewall is a better one of all.

IP are like two types Public and Private. We can eiter allow a public IP are a range of local IP using subnet.

Public IPs are basically globally unique and the router we get connected to access internet has its own public IP and our device will be assigned a Private IP using DHCP (Dynaic Host Control Protocol). 

All our requests inside our Local Area Network are baiscally done using Private IP and the connections outside our Router are handled by Public IP of router by sing something known as NAT (Network Address Translation).

So here as we are outside the Local Network of our cloud VM our SSH request is processed through Public IP whic we can find using ``curl `` 

We can allow requests from that Public IP so only people in the Local Network of that router can access SSH. We can use this to allow all connection through this public IP
```
sudo ufw allow from 203.0.113.5 to any port 22
sudo ufw delete allow ssh    // To delete our prev rule
sudo ufw reload              // To apply changes
```

To allow range of IP we can just use subnet mask something like 203.0.113.0/24 which basically allows all IPs in range of 203.0.113.1 - 203.0.113.255. (/24 says that 24 bits are like subnet mask and yhh remaining bits can be anything.)


But Yhh Public IP changes sometimes, if the router goes down or due to some other issue.

So, just tried it out once and removed the rule, as i might get locked out if something goes off.

### Fail2ban

Fail2ban is a security tool which protects our VM from brute force attacks.

We need to install fail2ban using ``sudo apt install fail2ban``

THen we need to two copy ``/etc/fail2ban/jail.conf`` to ``/etc/fail2ban/jail.local`` file where we make changes. It is done so as to prevent overwriting of .conf file when updates get installed.

In jail.local file under SSH daemon (sshd) section we add the following rules and they are kinda verbose, easy to undestand what they does. 

```
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

After that we need to restart fail2ban service.

### *Date: May 16th, 2025*
## Firewall and Network Security

### Firewall Configuration
Iptables are used for managing packet flow, Network Address Translation, Port Forwarding, etc.

Uncomplicated Firwall formely ufw is a basically a utility that is designed to simplify the setup and management of firewall rules and work with iptables.

Generally its installed on machine but if it's not we can install it using 
```
sudo apt install ufw
```

We can view list of iptables rules using command
```
iptables -L -v
```
They are basically divided into chains of rules (INPUT, OUTPUT, FORWARD).

We can use ufw to do iptables management for us to control network traffic.

Intially we can setup rule to allow all outgoing and deny all incomming traffic using

```
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

And let's get to allowing SSH on non-deafult port (eg. 2222)

For this we first need to allow connections to that port trough ufw, so we can just do
```
sudo ufw allow 2222/tcp
sudo ufw reload
```

Now we need to change ``Port`` in SSH daemon config to ``2222`` and restart SSH service.

Also we need to add This port on Azure Portal to allow connection. We can just create a new Inbound Port rule in Networking Section of our VM.

Now we can connect to SSH on port 2222.

We can also http and https on their default ports 80 and 443

```
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

To enable Logging we can use ``sudo ufw logging on`` and logs will automatically be saved to ``/var/log/ufw.log``


## User and Permission Management

### User Setup

Here to create users we can use ``sudo useradd -m username``. The -m flag automatically creates a home dir for the user and gives rex permisiions to only the user which is sufficient for us.

Btw we can always use `chmod` with sudo to configure permissions if anything goes off. You can always check permissions by using ``ls -lart /home`` and fix up things. 

So to create user exam_1 , exam_2 and exam_3 we need to run these three commands.

```
sudo useradd -m exam_1
sudo useradd -m exam_2
sudo useradd -m exam_3
```

We can also run the following to make sure permissions are correctly configured

```
sudo chmod 700 /home/exam_1
sudo chmod 700 /home/exam_2
sudo chmod 700 /home/exam_3
```

Now we need to create examadmin with sudo permissions using 

```
sudo useradd -m examadmin
sudo usermod -aG sudo examadmin   //adds sudo grp to examadmin
```

You can check groups by using ``groups username``

For examaudit which needs read access to all users home dir we use

```
sudo useradd -m examaudit
sudo usermod -aG exam_1,exam_2,exam_3 examaudit
```
As we added examaudit to all user groups, we can change permissions of grps to have read access. For that we run the following command.

```
sudo chmod 740 /home/exam_1
sudo chmod 740 /home/exam_2
sudo chmod 740 /home/exam_3
```

By only read access you can only read files whose names are known, but can list or traverse directories. To get those execute permission is needed. For that we need to use

```
sudo chmod 750 /home/exam_1
sudo chmod 750 /home/exam_2
sudo chmod 750 /home/exam_3
```
I used ``sudo passwd username`` to set passwords to all users. For convenience i used password same as username.

Finally, Though our examadmin has root priviliges cd to other user dirs is not possible though we can read and write files for outside directory. But can access those using root shell ``sudo -i``.

If we want examadmin to cd into all user directories without root shell, we can add all user groups to examadmin

```
sudo usermod -aG exam_1,exam_2,exam_3 examadmin
```
### *Date: May 17th, 2025*
### Home Directory Setup

To check permissions, we can use ls -lart /home and check all the permissions, because we already setup these in above steps.

Next to setup Disk Spaces to users 

For this we need to change ``/etc/fstab`` file and add ``usrquota`` beside defaults

Then we need to remount ``sudo mount -o remount /`` root dir and perform ``sudo quotacheck -cum /``.

We can start using quotas by ``sudo quotaon /`` but it is not supported in azure shell idk why but yhh for this to work there are some ways which i explored 

One way is to detach OS disk and attach it to a VM and do it as we need to umount , we can't do it when it is working as OS so we do it.

Other way is to use one external disk and setup quotas in it and use it to mount that in /home directory.

I might work on this later.

### Backup Script

Basically we can create bash file at /usr/local/bin/backup_exam_users.sh and use script below

```
#!/bin/bash

BACKUP_DIR="/var/backups/exam_users"
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y-%m-%d")
BACKUP_FILE="$BACKUP_DIR/exam_users_backup_$TIMESTAMP.tar.gz"

tar -czf "$BACKUP_FILE" /home/exam_*

chmod 600 "$BACKUP_FILE"
```

To restrict execution only to admin we can make admin as its owner and give permissions for only owner.
```
sudo chown examadmin:examadmin /usr/local/bin/backup_exam_users.sh
sudo chmod 700 /usr/local/bin/backup_exam_users.sh
```

If we want we can also make cron job for that so that it happens on certain intervals

```
sudo crontab -u examadmin -e
```

we can add this in the tab

```
@daily /usr/local/bin/backup_exam_users.sh
```

##  Web Server Deployment and Secure Configuration 

We can simply Install nginx using apt and we can set flag -y to automatically accept yes to all prompts
```
sudo apt install nginx -y
```
We can create a user with bash access using following command

```
sudo useradd -m -s /bin/bash appuser
```

We can passwd to the user , I used username as passwd for convinence.

We can switch to newly created user using the command ``su - appuser``

Now Initially I thought that I might get app from app and SHA256 signature using wget but it didn't worked well. So I used FileZilla to transfer the download app on windows to my VM. 

To check signature we need to edit signature. So I switched to sudo user and edited the signature to include name of app at last like

```
52ef28f5606aa8ad4aee09e723ee9b08f62fdca0aa86c1c01c1bb4d61a46e47c app1
```
We need to do so that checksum knows which file to check hash with.

These kind of signatures are used to verify that the file is not tampered.

We can use check sum to verify signature.

```
sha256sum -c app1.sha256.sig
```

If it's says ok then everything is fine.

Now We need to give execute permission by switching to sudo user 

```
sudo chmod +x ./app1
```

We can un it now just by executing it 
```
./app1
```

For app2 we can simply clone with HTTPS url 
```
git clone <url>
```

We can see its using bun by looking at bun.lockb

So to run that either we can use Docker or bun

For now i will go wit bun for that we need to run 
```
sudo apt install unzip -y
curl -fsSL https://bun.sh/install | bash
```
Restart shell and use ``bun --version`` to check installation.

Note:
Now for setting up a Reverse Proxy, since we are not assigned domains, I'm going to use the Public IP for that.

Comming to **Reverse Proxy**, it is basically configured infront of backend to to do tasks like load balancing, directing requests to specific server, etc.

It also helps us to hide the original IP of the backend serving as  security measure.

Also one advantage of reverse proxy is we don't need to remember port numbers of backend to interact with. We just send http or https request to ngnix and ngnix will handle.

Now as we installed our apps and ngnix, Let's setup Reverse Proxy!!!.

For this we need to define some rules for ngin. We can do that in ``/etc/nginx/sites-available/`` dir. This is the place where all nginx config files are placed.
we need to create a file in that dir and add our proxy rules. 
```
sudo nano /etc/nginx/sites-available/reverse-http
```

Now we can add our rules, We basically have three end points 

```
server {
    listen 80;
    server_name 9.234.160.46;

    location /server1/ {
        proxy_pass http://127.0.0.1:8008/server1;
    }

    location /server2/ {
        proxy_pass http://127.0.0.1:8008/;
      
    }

    location /sslopen/ {
        proxy_pass http://127.0.0.1:3000/sslopen/edit/token1;
    }
}
```

Our reverse-http file looks like this.

Let's go through those lines step y step

First we are defining that our nginx server to listen on port 80 i.e, http. We used our server name as public IP as we still not go any domain assigned. Then we specify our endpoints basically.

First one is on endpoint /server1, we are forwrding the request to localhost (which is 127.0.0.1) on port 8008, where our app1 is running.

Similarly we done for /server2.

Now for /sslopen after reading README I can we know that we can add env variable token assigned to some admin and send it as Dynamic parameter to acces Post form.

So I just added to example Variables in .env.example to .env and included token in request URL.

Now all our endpoints are working successfuly but as we are in Azure VM we need to set Inbound Port to Port 80 to access it from outside (Internet basically). I quickly did it on Azure Portal.

We can use cURL to check the Reverse proxy status.

As we don't have Inbound ports to Port 8008 and 3000 we can't access them from internet.

