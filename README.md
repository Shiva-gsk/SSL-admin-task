# SSL Admin Task Documentation
My documentation on SSL-admin Task basically has the following steps. You can use specific Links to get to the desired section.

1. [Initial Setup](#stage-1---intial-setup)
2. [Enhanced Security](#enhanced-security)
3. [Firewall and Network security](#firewall-and-network-security)
4. [User and Permission Management](#user-and-permission-management)
5. [Web Server Deployment and Secure Configuration](#web-server-deployment-and-secure-configuration)
6. [Database Security](#database-security)
7. [VPN Configuration](#vpn-configuration)
8. [Docker Fundamentals and Personal Website Development](#docker-fundamentals-and-personal-website-deployment)


### *Date: 14th May, 2025*
## Stage 1 - Intial Setup 
This Stage required me to rent a Cloud VM on Azure or some similar platform.
I was actually new to using such platforms, so it took me some time to understand about them.

I basically signup to Azure Platform and I got about $100 free credits that can be used for over 365 days. I created a static IP resource and a VM using Static IP that I created. Though an easy setup, this took me some time as I was to new to such platform.

Now after setting up VM our first task to enable unattended upgrades for security.

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

When i researched about this I came to know that there are actually different ways, but yeah using firewall is a better one of all.

IP are like two types Public and Private. We can either allow a public IP or a range of local IP using subnet.

Public IPs are basically globally unique and the router we get connected to access internet has its own public IP and our device will be assigned a Private IP using DHCP (Dynamic Host Control Protocol) by the Router. 

All our requests inside our Local Area Network are basically done using Private IP and the connections outside our Router are handled by Public IP of router by using something known as NAT (Network Address Translation).

So here as we are outside the Local Network of our cloud VM our SSH request is processed through Public IP which we can find using ``curl -4 ifconfig.me `` 

We can allow requests from that Public IP so only people in the Local Network of that router can access SSH. We can use this to allow all connection through this public IP
```
sudo ufw allow from 203.0.113.5 to any port 22
sudo ufw delete allow ssh    // To delete our prev rule
sudo ufw reload              // To apply changes
```

To allow range of IP we can just use subnet mask something like 203.0.113.0/24 which basically allows all IPs in range of 203.0.113.1 - 203.0.113.255. (/24 says that 24 bits are like subnet mask and yhh remaining bits can be anything.)


But Yhh Public IP changes sometimes, if the router goes down or due to DHCP by ISP or anyother thing..

So, just tried it out once and removed the rule, as I might get locked out if something goes off.

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

Finally, Though our examadmin has root priviliges `cd` to other user dirs is not possible though we can read and write files for outside directory. But can access those using root shell ``sudo -i``.

If we want examadmin to cd into all user directories without root shell, we can add all user groups to examadmin

```
sudo usermod -aG exam_1,exam_2,exam_3 examadmin
```
### *Date: May 17th, 2025*
### Home Directory Setup

To check permissions, we can use `ls -lart /home` and check all the permissions, because we already setup these in above steps.

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

### 1. Reverse Proxy Configuration

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

Now Initially I thought that I might get app and SHA256 signature using wget but it didn't worked well. So I used FileZilla to transfer the downloaded app on windows to my VM. 

To check signature we need to edit signature. So I switched to sudo user and edited the signature to include name of app at last like

```
52ef28f5606aa8ad4aee09e723ee9b08f62fdca0aa86c1c01c1bb4d61a46e47c app1
```
We need to do so that checksum knows which file to check the hash with.

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

For now i will go with bun. For that we need to run 
```
sudo apt install unzip -y
curl -fsSL https://bun.sh/install | bash
```
Restart shell and use ``bun --version`` to check installation.

**Note:**
Now for setting up a Reverse Proxy, since we are not assigned domains, I'm going to use the Public IP for that.

Comming to **Reverse Proxy**, it is basically configured infront of backend to to do tasks like load balancing, directing requests to specific server, etc.

It also helps us to hide the original IP of the backend serving as security measure in some cases.

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

We can use symlink to add our file to ``/etc/nginx/sites-enabled/``
```
sudo ln -s /etc/nginx/sites-available/reverse-http /etc/nginx/sites-enabled/
```

Then we can test the file using using
```
sudo nginx -t
```
As test are passed we can reload nginx to apply changes.
```
sudo systemctl reload nginx
```

Ok Now, Let's go through those lines step by step

First we are defining that our Nginx server to listen on port 80 i.e, http. We used our server name as public IP as we still not go any domain assigned. Then we specify our endpoints basically.

First one is on endpoint /server1, we are forwrding the request to localhost (which is 127.0.0.1) on port 8008, where our app1 is running.

Similarly we done for /server2.

Now for /sslopen after reading README I can we know that we can add env variable token assigned to some admin and send it as Dynamic parameter to access Post form.

So I just added to example Variables in .env.example to .env and included token in request URL.

Now all our endpoints are working successfuly but as we are in Azure VM we need to set Inbound Port to Port 80 to access it from outside (Internet basically). I quickly did it on Azure Portal.

We can use cURL to check the Reverse proxy status.

As we don't have Inbound ports to Port 8008 and 3000 we can't access them from internet.

We can create System deamon Service for these two apps so that they start to run on Boot up.

After searching abont daemon services I came to know we can set it up simply in ``/etc/systemd/system/`` dir by creating a .service file.

My service file for app1 look like this

```
[Unit]
Description=App1 Service
After=network.target

[Service]
User=appuser
ExecStart=/home/appuser/app1
Restart=always

[Install]
WantedBy=multi-user.target
```
We Just can make sure the Working dir and Start command to start the app.

Now for issslopen it tooks similar we just need to change working dir and start command.

```
[Unit]
Description=IsSSLOpen Service
After=network.target

[Service]
User=appuser
WorkingDirectory=/home/appuser/issslopen
ExecStart=/home/appuser/.bun/bin/bun index.ts
Restart=always

[Install]
WantedBy=multi-user.target
```

As we know we are using bun to run the app.

Now these apps and Reverse Proxy is fully functional.


### Content Security Policy

CSP is a browser-side security feature that helps prevent Cross-site-scripting (XSS) and other code injection attacks by telling the browser which sources of content are allowed to load.

After browsing through internet i got a full secure Content-policy which is below
```
Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
```
Now Let's try to understand these one by one.

1. default-src 'self'  : Default fallback policy allowing scripts, images,.. from same domain only!
2. script-src 'self'   : Allows Js files from only same domain.
3. style-src 'self'    : Allows CSS only from same domain (Blocks inline and 3rd party CSS)
4. img-src 'self' data : Allows images only from  same domain
5. object-src 'none'    : Disallows usage of `<object>` and `<embed>` like tags.
6. frame-ancestors 'none' : Prevents websites to be embedded in iframes.
7. base-uri 'self'  : 	Limits the `<base>` HTML tag to only allow self-origin URLs.
8. form-action 'self' : Restricts where forms on our site can submit data to, allowing only our servers to receive form data.
9. always  : thisis nginx specific to add make sure headers are always added.

We can add it in our `reverse-http` file we created above . We can place below code under server name
```
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
```
and then we need to test and reload nginx again to make changes applied.

```
sudo nginx -t
sudo systemctl reload nginx
```

Now our Websites also have CSP enabled!!

**UPDATE** : Though Domain is assigned to my VM, I'm just leaving my Reverse Proxy on my VM IP, as the domain will simply resolved to my VM IP and Ngnix takes the request on VM IP.


## Database Security

### 1. Database Setup

Mariadb is an Open source RDMS which serves as alternative to MySQL with betterperformance and better community support.

We can install it by 
```
sudo apt install mariadb-server -y  
```
Again -y flag to say yes to installation prompt.

We can start mariadb service using systemctl

```
sudo systemctl start mariadb
```

Then we can run ``sudo mysql_secure_installation`` to set up basic db security, We can disable root login from this.

We can login to mariadb using 
```
sudo mysql -u root -p
```

To crate database we an use 
```
CREATE DATABASE secure_onboarding;
```

Then created a onboarding_user with same password as username.

```
CREATE USER 'onboarding_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
```

WE can give the onboarding_user minimal permissions like SELECT, INSERT, UPDATE and DELETE and apply Privilages.
```
GRANT SELECT, INSERT, UPDATE, DELETE ON secure_onboarding.* TO 'onboarding_user'@'localhost';
FLUSH PRIVILEGES;
```
### 2. Database Security

To Ensure remote root login is disabled we can just UPDATE the host of root to ``localhost`` and then EXIT ``mariadb repl``.

```
UPDATE mysql.user SET Host='localhost' WHERE User='root';
FLUSH PRIVILEGES;
EXIT;
```
Now to ensure that our server is only accesable through localhost we can bind it it our localhost IP which is 127.0.0.1.

We can do it by ensuring the binding address in its config file. We can go to this file
```
sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
```
and change 
```
bind-address = 127.0.0.1
```
Then we need to restart our mariadb service to apply changes.

For backup we can just create a script at
```
sudo nano /usr/local/bin/db_backup.sh
```

and use following script to do it.

```
#!/bin/bash
DB_NAME="secure_onboarding"
DB_USER="root"
DB_PASS="Shivak"
BACKUP_DIR="/var/backups/mariadb"
DATE=$(date +%F_%T)

mkdir -p $BACKUP_DIR
mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/${DB_NAME}_$DATE.sql
find $BACKUP_DIR -type f -mtime +7 -delete
```

Let's go through script, Intially we declared all required variables like DB_NAME, etc.

and we are creating BackUp dir using -p flag to ensure it only happens if it doesn't exist. 

Also we are using mysqldump to store ur data backup and also delete older backups specifically 7 days (Yhh as stroge will be issue if we keep older files).


## VPN Configuration 
WireGuard is a modern fast and secure VPN protocol. We can use it to create a virtual Local Network and yhh we can use NAT to send requests through VPN server Public IP. For this I am using my VM as 

```
sudo apt install wireguard
```

So now we need to setup server configuration in our VM and a Client configuration in our PC. 

Actually for this we need to generate 2 pair of public private key, one in server and one in client.

We can create one using wireguard command line utility.

```
wg genkey | tee privatekey | wg pubkey > publickey
```

The genkey command generates a Private key and we write it into a file named privatekey and pipe the input to pubkey command which generates corresponding Public key and write it to a file named public key.

Then we need to create a conf file for a Virtual Network Interface and and configure it.

```
[Interface]
Address = 10.0.0.1/24
PrivateKey = <server_private_key>
ListenPort = 51820

```

We are setting our Vnet on IP 10.0.0.1 with subnet of 24 bits. And adding our Private key and Assigning a port to listen on 51820 which is default for UDP Port for WireGuard.

Now Similary, We need to Create a Client Interface and add Server Public Key to Client and Client Public key to Sever For them to exchange Packets.

As Im using Windows as my client(😅) I'm using Wireguard Application for Windows. And Create a Tunnel Interface.

```
[Interface]
PrivateKey = xxxxxxxxx
Address = 10.0.0.2/8

[Peer]
PublicKey = xxxxxxxxxxxxxxx
AllowedIPs = 0.0.0.0/0
Endpoint = 9.234.160.46:51820
PersistentKeepalive = 25
```

Now, we Need to add client public key to server conf so that it verifies and accepts requests from client.

## Docker Fundamentals and Personal Website Deployment 

### 1. Basic Docker Setup

For this we need to install few prerequisite packages which let apt to use packages over HTTPS.
```
sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
```
Now we need to add Official Docker GPG key (Similar to public key) on our machine, so that while installing any packages we can make sure that they are originally from Docker Inc.

We can just run this command to download Dockey key and store it.
```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
```
They key will be saved to `/usr/share/keyrings`

Now we need to add Docker Repo to APT sources for that we use
```
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

Now we can install our docker Engine
```
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io -y
```

We can rnable docker using systemctl so that it starts on boot
```
sudo systemctl enable docker
```

Now we can add our user to docker using
```
sudo usermod -aG docker $USER
```
Now we can logout and login or just use ``newgrp docker`` to get permission to run docker containers.

Lets try runnig `hello-world` image
```
docker run hello-world
```

### 2. Deploying a Portfolio Website via Docker and Nginx

For this I used FileZilla again to transfer my portfolio to VM and then created Dockerfile and .dockerignore files. The Portfolio is basically written In NextJS.

Now we can create a docker image 
```
docker build -t portfolio .
```

We can create a volume using
```
docker volume create nextjs_data
```
and run the container with
```
docker run -d --name my-porfolio   -p 5555:3000   -v nextjs_data:/app/data   --cap-add=NET_ADMIN    portfolio
```
Here the flags `-d` means run in detached mode (not bound to shell/terminal) , `-p` help to connect port 5555 of docker to 3000 on pc `-v` to mount volume.

Due to issues with NextJs and Reverse Proxy Javascript is not being loading (Hydration) and my website is not Interactive. I might lokk into this later.

And now to run this on bootup we need to create a service. We can just create a file with portfolio.serve name.

```
sudo nano /etc/systemd/system/portfolio.service
```
Now we can add our Configuration to it

```
[Unit]
Description=Portfolio Docker Container
After=docker.service
Requires=docker.service

[Service]
Restart=always
ExecStart=/usr/bin/docker start -a my-portfolio
ExecStop=/usr/bin/docker stop -t 2 my-portfolio

[Install]
WantedBy=multi-user.target
```

This Just says to start container when system boots up.

Now we can use following commands to re-execute and reload files into systemd
```
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
```

Now we can start our porfolio service
```
sudo systemctl enable portfolio.service
sudo systemctl start portfolio.service
```

Now i setup my reverse proxy for this website on location /portfolio

```
location /_next/static/ {
    proxy_pass http://localhost:5555/_next/static/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /portfolio {
    proxy_pass http://localhost:5555/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
}
```
First one to direct the resource fetching and second location for my actual website.

Now I get to know that as Iam using reverse proxy, my nextjsapp is getting confused on where to fetch resources(Its searching on ./portfolio/_next/.. but needs to search on ./_next/..). 

After surfing though internet, i got to know that we just need to configure next.config.ts file and specify our proxy route as basePath and assetPath.

```
const nextConfig: NextConfig = {
  basePath: "/portfolio",
  assetPrefix: '/portfolio/',
};
```
Now our routes are correctly configured, but still CSP is not allowing hydration (might be due to script 'self' tag in CSP header).

So, I specifically wrote a header on portfolio section.

```
    location /_next/static/ {
        proxy_pass http://localhost:5555/_next/static/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /portfolio/ {
          add_header Content-Security-Policy "
          default-src 'self';
          script-src 'self' 'unsafe-inline' 'unsafe-eval';
          style-src 'self' 'unsafe-inline';
          img-src 'self' data:;
          font-src 'self' data:;
          connect-src 'self' https:;
          frame-ancestors 'none';
          object-src 'none';
          base-uri 'self';
          form-action 'self';
        " always;
        proxy_pass http://localhost:5555/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
```
Thankfully, there are plenty of nice resources on Internet over there to guide me through my setup Process.

Actually I don't need the first proxy location on /_next/static as /portfolio route automatically manages and sends request if the next.config.ts is correctly configured for reverse proxy. So we can remove it.

```
location /portfolio/ {
    add_header Content-Security-Policy "
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    font-src 'self' data:;
    connect-src 'self' https:;
    frame-ancestors 'none';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    manifest-src 'self';
    media-src 'self';
    " always;

    proxy_pass http://localhost:5555/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
}
```

This is the only thing i need extra in my ``/etc/nginx/sites-available/reverse-http`` file.

Finally, Our reverse proxy is functional . YAY!!

You can access my porfolio now on http://9.234.160.46/portfolio

**UPDATE** : Though Domain is assigned to my VM, I'm just leaving my Reverse Proxy on my VM IP, as the domain will simply resolved to my VM IP and Ngnix takes the request on VM IP.
