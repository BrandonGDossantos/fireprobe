#!/bin/sh
iptables -F
iptables -X

iptables -A OUTPUT -p udp --sport 88 -m iprange --dst-range 44.44.0.3-44.44.10.3 -j DROP
iptables -A INPUT -p udp --dport 34:45 -m iprange --src-range 19.0.0.2 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 122.33.22.0/24 -j DROP
iptables -A OUTPUT -p tcp --dport 33 -s 10.50.0.0/16 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 53566 -d 222.222.222.222 -j ACCEPT 
iptables -A INPUT -p tcp --dport 23 -s 1.2.3.4 -d 129.192.129.192 -j DROP 
iptables -A INPUT -p tcp --dport 100:110 -m iprange --src-range 192.188.229.0-192.255.255.255 -j DROP
iptables -A INPUT -p tcp --destination-port 100:130 -m iprange --src-range 142.192.0.0-142.192.255.255 -j ACCEPT
iptables -A INPUT -p tcp --dport 7777 -m iprange --src-range 192.188.229.0-192.255.255.255 --dst-range 122.222.222.0-122.222.222.255 -j DROP
iptables -A OUTPUT -p tcp --sport 22 -s 1.2.3.4 -d 129.192.129.192 -j DROP 
