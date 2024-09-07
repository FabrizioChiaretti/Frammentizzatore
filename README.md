# Frammentizzatore
**Frammentizzatore** is a tool written in Python intercepting the local IPv6 outbound traffic and applying a custom fragmentation. It gives also the possibility to modify the extension headers chain of IPv6 packets and to add new extension headers in order to create a new chain of headers.    

## Getting Started

### Prerequisites
The tool can be run on a Linux machine and it is required to install version 3 of Python. The external dependencies to download are:

- NetfilterQueue ([https://pypi.org/project/NetfilterQueue/]), that provides to a user space program to access to packets matched by an iptables rule in Linux;

- Scapy ([https://scapy.readthedocs.io/en/latest/]), that is a Python program that enables to send, sniff, and manipulate network packets.

### Installation and set up
In order to install the tool the following steps are required:

- Create a directory  
`
mkdir mydir
`
- Go into the new directory  
`
cd mydir
`
- Initialize an empty repository  
`
git init
`  
- Clone the repository  
`
git clone [https://github.com/FabrizioChiaretti/Frammentizzatore.git]
`
- Execute the runner.py program located in Frammentizzatore directory as root user    
`
cd Frammentizzatore
`  
`
sudo -E python3 runner.py
`  

When the tool is runnning info logs are shown on command line.

![Screenshot 2024-09-07 153459](https://github.com/user-attachments/assets/8523c702-f9c2-42a8-8ce5-bf1970f83b15)


## Usage
