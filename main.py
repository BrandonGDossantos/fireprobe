import iptc
from netaddr import IPAddress
import argparse
import ipaddress

PROTO_MAP = {'tcp':6, 'udp':17, None:6, 'None':6}
IP_MAP = {'0.0.0.0/0.0.0.0': (0, 4294967295), 'None':(0, 4294967295), None:(0, 4294967295)}
# socket get proto by name
PRT_MAP = {'None':(0, 65535), None:(0,65535)}
ACTION_MAP = {'ACCEPT': (0, 0), 'DROP':(1, 1), None:(1, 1)}

RULE_OBJ_LIST = []
PROJECTED_RULES = []

class Rule(object):
	def __init__(self, protocol=None, src=None, dst=None, sport=None, dport=None, action=None, srcRange=None, dstRange=None):
		self.set_protocol(protocol)
		self.set_pairs(src, srcRange, sport, dst, dstRange, dport)
		self.set_action(action)

	def set_protocol(self, protocol):
			self.protocol = (PROTO_MAP[protocol], PROTO_MAP[protocol])
	def set_pairs(self, src, srcRange, sport, dst, dstRange, dport):
		if (srcRange == 'None' or srcRange == None)  and (dstRange == 'None' or dstRange == None):
				self.src = set_ip(src)
				self.dst = set_ip(dst)
				self.sport = set_port(sport)
				self.dport = set_port(dport)
		else:
			self.src = set_ip_range(srcRange)
			self.dst = set_ip_range(dstRange)
			self.sport = set_port(sport)
			self.dport = set_port(dport)
	def set_action(self, action):
		self.action = ACTION_MAP[action]
	

def get_tuple(obj):
	values = []
	for x in vars(obj).items():
		values.append(x)
	return dict(values)

def set_ip(ip):
	if ip in IP_MAP:
		return IP_MAP[ip]
	else:
		ipaddr, netmask = ip.split('/')
		split_ip = ipaddress.IPv4Network(u'{}'.format("{}/{}".format(ipaddr, IPAddress(netmask).netmask_bits())))
		
		return tuple([int(IPAddress(str(split_ip[0]))), int(IPAddress(str(split_ip[-1])))])
		 
def set_ip_range(ip):
	if ip in IP_MAP:
		return IP_MAP[ip]
	else:
		split_ip = ip.split('-')
		return tuple([int(IPAddress(str(split_ip[0]))), int(IPAddress(str(split_ip[1])))])

def set_port(port):
	if port in PRT_MAP:
		return PRT_MAP[port]
	else: 
		split_port = [int(x) for x in port.split(':')]
		if len(split_port) == 1:
			split_port.append(int(split_port[0]))
		return tuple(split_port)
<<<<<<< HEAD
		
def projection(property_rule, firewall_rules):
	for firewall_rule in firewall_rules:
		for k in firewall_rule.keys():
			if (firewall_rule[k][1] < property_rule[k][0]) or (firewall_rule[k][0] > property_rule[k][1]):
				left, right = firewall_rule[k][0], firewall_rule[k][1]
			else:
					if property_rule[k][0] > firewall_rule[k][0]:
						left = property_rule[k][0]
					else:
						left = firewall_rule[k][0]
					if property_rule[k][1] > firewall_rule[k][1]:
						right = firewall_rule[k][1]
					else:
						right = property_rule[k][1]
			print("-------------------")
			print("Firewall Rule {} : {}".format(k, firewall_rule[k]))
			print("Property {} : {}".format(k, property_rule[k]))
			print("\tProjected {} : {}".format(k, tuple([left, right])))
		print("=====================")
=======
>>>>>>> 4707c9a1016f075f5c5efce7cbf5051a7f301e5a

def print_rule_objects(obj_list):
	for obj in obj_list:
		print("="*170)
		print(obj)

def print_orig(rule, match, y):
	print("**************Original-{}********************".format(y))
	print("Protocol: {}".format(rule.protocol))
	print("Src: {}".format(rule.src))
	print("Dst: {}".format(rule.dst))
	print("Src Range: {}".format(match.src_range))
	print("Dst Range: {}".format(match.dst_range))
	print("Sport: {}".format(match.sport))
	print("Dport: {}".format(match.dport))
	print("Action: {}".format(rule.target.name))

def printTupList(t):
	for obj in t.list:
		print(obj.tup)
		print("\n")

def extract(table):
	for chain in table.chains:
		for rule in chain.rules:
			rule_obj = Rule()
			y = 0
			for match in rule.matches:
				y+=1
				rule_obj.set_protocol(str(rule.protocol))		
				rule_obj.set_pairs(str(rule.src), str(match.src_range), str(match.sport), str(rule.dst), str(match.dst_range), str(match.dport))
				rule_obj.set_action(str(rule.target.name))
				if y == len(rule.matches):
					RULE_OBJ_LIST.append(get_tuple(rule_obj))
<<<<<<< HEAD
def main():	
	parser = argparse.ArgumentParser(description='Tool to check if an iptables firewall satisfies a given property.')
	parser.add_argument("-p", "--protocol", help="Protocol: tcp, udp")
	parser.add_argument("-s", "--src", help="Source address: 192.168.1.12 or 192.168.1.0/24")
	parser.add_argument("-sr", "--srcRange", help="Source range: 0.0.0.0-255.255.255.255 or 192.168.1.2-192.168.2.3")
	parser.add_argument("-d", "--dst", help="Destination address: 172.129.1.10 or 172.129.1.10/32")
	parser.add_argument("-dr", "--dstRange", help="Destination range: 0.0.0.0-255.255.255.255 or 42.11.9.1-41.11.10.2")
	parser.add_argument("-sp", "--sport", help="Source Port: 22 or 22:23")
	parser.add_argument("-dp", "--dport", help="Destination Port: '21' or '24:25'")
	parser.add_argument("-a", "--action", help="ACCEPT '0' or DROP '1'")
	args = parser.parse_args()
	property_rule = Rule(args.protocol, args.src, args.dst, args.sport, args.dport, args.action, args.srcRange, args.dstRange)
	print(property_rule.__dict__)
=======
# (first octet * 256)^3 + (second octect * 256)^2 + (third octect * 256)^1 + (fourth octect * 256)^0
def ip2int(addr):
	array = str(addr).split(".")
	ipAsInt = (int(array[0]) * 256^3) + (int(array[1]) * 256^2) + (int(array[2]) * 256^1) + (int(array[3]) * 256^0)
	return ipAsInt

def main():
>>>>>>> 4707c9a1016f075f5c5efce7cbf5051a7f301e5a
	extract(iptc.Table(iptc.Table.FILTER))
	projection(property_rule.__dict__, RULE_OBJ_LIST)
if __name__ == "__main__":
	main()
