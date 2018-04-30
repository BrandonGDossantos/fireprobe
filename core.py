import itertools
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
END_POINTS = []
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

# returns a dictionary of every value where the key is the value within the class
# the value is the value within the class
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
		
def projection(property_rule, firewall_rules):
	projected_firewall = []
	for firewall_rule in firewall_rules:
		projected_rule = {}
		for k in firewall_rule.keys():
			projected_rule[k] = check_overlaps(firewall_rule, property_rule, k)
		projected_firewall.append(projected_rule)
	return clean_projections(projected_firewall)

def check_overlaps(firewall_rule, property_rule, k):
	if k == 'action':
		return firewall_rule[k][0]
	if (firewall_rule[k][1] < property_rule[k][0]) or (firewall_rule[k][0] > property_rule[k][1]):
		return None
	else:
		if property_rule[k][0] > firewall_rule[k][0]:
			left = property_rule[k][0]
		else:
			left = firewall_rule[k][0]
		if property_rule[k][1] > firewall_rule[k][1]:
			right = firewall_rule[k][1]
		else:
			right = property_rule[k][1]
	return tuple([left, right])

def clean_projections(PROJECTED_FIREWALL):
	clean_projected_firewall = []
	for rule in PROJECTED_FIREWALL:
		if None not in rule.values():
			clean_projected_firewall.append(rule)
	return clean_projected_firewall

def end_points(property_rule, projected_firewall):
	end_points = {}
	property_action = property_rule['action'][0]
	for rule in projected_firewall:
		if rule['action'] == property_action:
			for k in rule.keys():
				if k != 'action':
					if (rule[k][1]+1) <= property_rule[k][1]:
						end_points.setdefault(k, []).append((rule[k][1])+1)
		else:
			for k in rule.keys():
				if k != 'action':
					end_points.setdefault(k, []).append(rule[k][0])
	return remove_duplicates(end_points)

def cartesian(end_point_list):
	return (dict(zip(end_point_list, x)) for x in itertools.product(*end_point_list.values()))

def remove_duplicates(end_points):
	removed_duplicates = {}
	for k in end_points.keys():
		removed_duplicates[k] = list(set(end_points[k]))
	return removed_duplicates

def launch_probes(witness_packets, RULE_OBJ_LIST):
	resolved_witness = {}
	for packet in witness_packets:
		for rule in RULE_OBJ_LIST:
			dont_add = False
			for k in packet.keys():
				print(rule[k][0])
				print(rule[k][1])
				if packet[k] in range(rule[k][0], rule[k][1]):
					pass
				else:
					dont_add = True
					break
			
			if not dont_add:
				index_packet = witness_packets.index(packet)
				if resolved_witness.has_key(index_packet):
					continue
				else:
					resolved_witness[index_packet] = rule['action'][0]
	return resolved_witness

def clean_resolved_witness(resolved_witness, witness_packets, property_action):
	least_witness = []
	# resolved_witness = {0:1, 1:0, 2:0, 3:1, 4:0, 5:0}
	for k,v in resolved_witness.items():
		if v != property_action:
			least_witness.append(witness_packets[k])		
	return least_witness
def alert_user(least_witness):
	if not least_witness:
		print("\n==================================================")
		print("=======  No least witness packets found.   =======")
		print("======= Firewall properties are effective. =======")
		print("==================================================")
	else:
		#print(least_witness)
		print("\n==================================================")
		print("===== Least witness packets were discovered! =====")
		print("==================================================")
		n = 1
		for packet in least_witness:
			print("\n" + str(n) + " **** Least witness packet property ****")
			print(packet)
			n = n + 1

# go for every chain, then every rule in the chain, then sets the values 
# creates the rule object list
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
	extract(iptc.Table(iptc.Table.FILTER))
	projected_firewall = projection(property_rule.__dict__, RULE_OBJ_LIST)
	print(projected_firewall)
	end_point_list = end_points(property_rule.__dict__, projected_firewall)
	witness_packets = list(cartesian(end_point_list))
	resolved_witness = launch_probes(witness_packets, RULE_OBJ_LIST)
	least_witness = clean_resolved_witness(resolved_witness, witness_packets, property_rule.action)
	alert_user(least_witness)
if __name__ == "__main__":
	main()
