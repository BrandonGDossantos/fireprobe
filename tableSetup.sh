#!/bin/sh
iptables -F
iptables -X


iptables -A INPUT -p tcp --sport 122 --dport 22 -s 13.3.3.3/8 -j ACCEPT
iptables -A INPUT -p udp --sport 88 -m iprange --dst-range 44.44.0.3-44.44.10.3 -j DROP
iptables -A INPUT -p udp --dport 999 -s 19.0.0.0/8 -j DROP
iptables -A INPUT -p udp --dport 44444 --sport 55555 -m iprange --src-range 3.3.3.3-3.3.3.4 -j DROP
iptables -A INPUT -p udp --dport 34:45 -s 19.0.0.2 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m iprange --src-range 122.33.22.0-122.33.22.255 -j DROP
iptables -A INPUT -p tcp --dport 33 -m iprange --dst-range 10.50.0.0-10.50.255.255 -j ACCEPT
iptables -A INPUT -p tcp --sport 53566 -m iprange --dst-range 222.222.222.222 -j ACCEPT 
iptables -A INPUT -p tcp --dport 23 -m iprange --src-range 1.2.3.4 --dst-range 129.192.129.192 -j DROP 
iptables -A INPUT -p tcp --dport 100:110 -m iprange --src-range 192.188.229.0-192.255.255.255 -j DROP
iptables -A INPUT -p tcp --destination-port 100:130 -m iprange --src-range 142.192.0.0-142.192.255.255 -j ACCEPT
iptables -A INPUT -p tcp --dport 7777 -m iprange --src-range 192.188.229.0-192.255.255.255 --dst-range 122.222.222.0-122.222.222.255 -j DROP
iptables -A INPUT -p tcp --sport 22 -m iprange --src-range 1.2.3.4 --dst-range 129.192.129.192 -j DROP 
