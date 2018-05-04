# Fire Probe

We are looking for a packet that is resolved differently by the firewall and the property.
The probe attempts to find the witness packet. Some packet such that the firewall and the property resolve it differently.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

python 2.7 and iptables 

### Installing

`git clone https://github.com/BrandonGDossantos/fireprobe.git`

### Theory

Firewall: sequence of n rules

Each n rule has the form: (**<field 1>**, **<field 2>**,...) -> **Action**
______________________________________________________________________________________________________________

**Practical Firewall Rule**:

*Source Address Range*: 192.168.1.0/24

*Destination Address Range*: 192.168.2.3-192.168.2.5

*Source Port Range*: 22

*Destination Port Range*: *

*Protocol*: tcp

*Action*: Drop

(**(192.168.1.0,192.168.1.255)**,**(192.168.2.3,192.168.2.5)**,**(22,22)**,**(0,65565)**,**(6,6)**) -> **1**
______________________________________________________________________________________________________________
**Mock Firewall Rule**:

*Source Address Range*: 10-110

*Destination Address Range*: 90-190

(**(10,110)**,**(90,190)**) -> **0**

______________________________________________________________________________________________________________




Where each field is a range of values that define the field. 


Practical firewall example:


(SRC IP=141.192.*.*, PROTO=6, DPORT=100-110) -> ACCEPT

$ iptables -A INPUT -p tcp -m iprange --src-range 141.192.0.0-141.192.255.255 --dport 100:110 -j ACCEPT


### How to ?

1. Run `python core.py -h` for help. 

2. Make sure there is an existing iptable with rules. 

3. Input python property rule values

4. Run `python core.py` to launch probes!

### Break down into end to end tests

Run `python test_projection.py` to run the algorithm against a mock firewall and a test property. 

### And coding style tests

Tests launch probes against the projected firewall to find any least witness packets. 

## Authors

* **Brandon Dossantos** - *Algorithm work* - [BrandonGDossantos](https://github.com/BrandonGDossantos)
* **Daniel Slapelis** - *Test implementation* - [wegotthekeys](https://github.com/wegotthekeys)

## Acknowledgments

* Rochester Institute of Technology 
* Network Security and Forensics
* Professor: H.B. Acharya


