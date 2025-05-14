# SSL Admin Task Documentation
My documentation on SSL-admin Task basically has the following steps. you can use specific Links to get to the desired section.

1. [Initial Setup](#stage-1---intial-setup)
2. [Enhanced Security](#enhanced-security)
<!-- 3. []() -->


### *Date: 14th May, 2025*
## Stage 1 - Intial Setup 
This Stage required me to rent a Cloud VM on Azure or some similar platform.
I was actually new to using such platforms, so it took me some time to understand about them.

I basically signup to Azure Platform and I got about $100 free credits that can be used for over 365 days. I created a static IP resource and a VM using Static IP that I created. Though an easy setup, this took me some time as I was to new to such platform.

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

- Private key should be kept secret, and public key is used to verify the signature to verify access.

In the context of SSH here we store our private key on our device and while using SSH we run the following command to get access to remote pc's shell.

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
    
### Disabling Root Login

For this we need to go to SSH daemon config file which is located at ``/etc/ssh/sshd_config`` and change ``PermitRootLogin`` to ``no``.

This basically prevents brute force password attacks on root as its basically well-known username.

### Disable Password Authentication

Similar to root login we need to change the ``PasswordAuthentication`` to ``no`` in the same SSH daemon config file.



