### *Date: 14th May, 2025*
## Stage 1 - Intial Setup 
This Stage required me to rent a Cloud VM on Azure or some similar platform.
I was actually new to using such platforms, so it took me some time to understand about them.

I basically signup to Azure Platform and I got about $100 free credits that can be used for over 365 days. I created a static IP resource and a VM using Static IP that I created. Though an easy setup, this took me some time as I was to new to such platform.

Following Commands are used to setup unattended upgrades making sure system always receives latest security upgrades.

```
sudo apt update
sudo apt install unattended-upgrades apt-listchanges
sudo dpkg-reconfigure --priority=low unattended-upgrades
```


