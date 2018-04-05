#!/bin/sh
iptables -F
iptables -X

iptables -A OUTPUT -p tcp --sport 53566 -d 222.222.222.222 -j ACCEPT 
iptables -A INPUT -p tcp --dport 23 -s 1.2.3.4 -d 129.192.129.192 -j DROP 
iptables -A INPUT -p tcp --dport 100:110 -m iprange --src-range 192.188.229.0-192.255.255.255 -j DROP
iptables -A INPUT -p tcp --destination-port 100:130 -m iprange --src-range 142.192.0.0-142.192.255.255 -j ACCEPT
iptables -A INPUT -p tcp --dport 7777 -m iprange --src-range 192.188.229.0-192.255.255.255 --dst-range 122.222.222.0-122.222.222.255 -j DROP
iptables -A OUTPUT -p tcp --sport 22 -s 1.2.3.4 -d 129.192.129.192 -j DROP 
