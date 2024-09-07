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

When the tool is runnning info logs are shown on command line

![Screenshot 2024-09-07 160112](https://github.com/user-attachments/assets/da357795-f9e5-4deb-96e2-162f497d1a7d)

Type **Ctrl**`+`**c**  for stopping the program 

![Screenshot 2024-09-07 160129](https://github.com/user-attachments/assets/93150d64-9105-4d11-b439-5bf899d3fe01)

## Usage
The tool can be configured by filling the records of the **input.json** file. The following records define when, how and which IPv6 packets are intercepted and processed by the program:  

- **table**  
MANGLE  
FILTER
Empty string stands for FILTER (default)
- **chain**  
POSTROUTING/OUTPUT for mangle table  
OUTPUT for filter table 
- **protocol**  
TCP UDP ICMPv6 ESP AH  (any combination)
Empty string stands for TCP UDP ICMPv6 (default)
- **dstPort**  
Integer number between 0-65535 when protocol is either TCP or UDP or both  
Negative number stands for any port (default)  
- **ipv6Dest**  
IPv6 address of the receiver of the packets
Empty string stands for any IPv6 address (default)

According to the values of the above records, new rules are added on the **ip6tables** module of the Linux kernel and all the packets matching one of these rules are manipulated by the tool.  

Example

![Screenshot 2024-09-07 164801](https://github.com/user-attachments/assets/dc0d2814-28b6-43ba-95c5-fda871c524a3)

![Screenshot 2024-09-07 165113](https://github.com/user-attachments/assets/b849bbc5-d205-40e8-882c-a7c406cc88ba)

Once the IPv6 flow is described, the user has to specify the type of fragmentation to apply to the packets belonging to this flow. This is the purpose of the **type** record:
- "*Regular*" fragmentation stands for the usual fragmentation that is applied to packets by an operating system. The user can just specify the size of each fragment except the last one by the **fragmentSize** record (1280 is the maximum size supported).  
If the fragment size is not big enough so that the whole extension headers chain can not be located in the first fragment, the tool returns an error and the original packet that should be fragmented is released.

- "*Overlapping*" fragmentation refers to a custom fragmentation. By the **fragments** record, the user can decide of each fragment which is the lenght of the portion of the original packet payload to be carried (**PayloadLenght**), the value of the hop limit field (**HopLimit**), the fragment offset (**FO**), the value of the "More Fragment" flag (**M**) and, optionally, the indexes of the chunk of bytes to be carried (**indexes**).
Since the fragments offset is expressed in 8-octets, the values of **FO** and **PayloadLenght** fileds must be a positive integer and a multiple of 8, therefore the tool does not use the 8-octects notation. For the fragment having **M** flag set to 0 (the last fragment), the value of **PayloadLenght** can be whatever positive number or negative number: in the first case the original payload will be potentially truncated and in the second case the last index of the chunk carried by the fragment is the index of the last byte of the original payload.
By default when fragments overlap, each permutation of the fragments is sent to the destination, therefore the fragments are sent multiple times in a different order. The user can perform a single test by setting the **singleTest** record to 1, in this case the fragments are sent just once taking into account the order specified in the **fragments** record.

- "*Headerchain*" type provides to the user the possibility to modify or define the IPv6 extension headers chain of intercepted packets. When just "headerchain" is specified, the user can modify the order of the extension headers of the original packets and add new extension headers.
This option can be combined with overlapping fragmentation and regular fragmentation, therefore "*Overlapping-Headerchain*" and "*Regular-Headerchain*" fragmentation types are supported. They allow the user to manipulate the extension headers chain of each fragment by specifying the names of the extensions headers in the **HeaderChain** field of the **fragments** record.
The extension headers that can be added to packets are Hop-by-Hop Option header, Routing header, Destination Option header and Fragment header (even a duplicate). Authentication header (AH) and Encapsulating Security Payload (ESP) can not be added, but when they are already located in the intercepted packets, they can be specified in the **HeaderChain** field.
If the user choose "*Headerchain*" type, it is required to add just an item in the **fragments** record and when the user choose "*Regular-Headerchain*" type it is required to add an item in the **fragments** record for each fragment that will be created by the tool.

Example on how to specify the extension headers chain of either a fragment or the original packet
![Screenshot 2024-09-07 191452](https://github.com/user-attachments/assets/166185a0-c408-4497-9650-305673df61e8)

The user find an example of "*Overlapping-Headerchain*" fragmentation type in the **input.json** file when downloading the project.
















