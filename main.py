import iptc
from netaddr import IPAddress
import ipaddress

PROTO_MAP = {'tcp':6, 'udp':17}
SRC_MAP = {'0.0.0.0/0.0.0.0': ('0.0.0.0', '255.255.255.255'), 'None':('0.0.0.0', '255.255.255.255')}
PRT_MAP = {'None':(0, 65535)}
ACTION_MAP = {'ACCEPT': 0, 'DROP':1}

RULE_OBJ_LIST = []

class Rule(object):
	def set_protocol(self, protocol):
			self.protocol = (PROTO_MAP[protocol], PROTO_MAP[protocol])
	def set_pairs(self, src, srcRange, sport, dst, dstRange, dport):
		if srcRange == 'None' and dstRange == 'None':
				self.src = clean_ip(src)
				self.dst = clean_ip(dst)
				self.sport = clean_port(sport)
				self.dport = clean_port(dport)
		else:
			self.src = clean_ip_range(srcRange)
			self.dst = clean_ip_range(dstRange)
	def set_action(self, action):
		self.action = ACTION_MAP[action]

def get_tuple(obj):
	values = []
	for x in vars(obj).items():
		values.append(x)
	return tuple(values)

def clean_ip(ip):
	try:
		return SRC_MAP[ip]
	except KeyError:
		ipaddr, netmask = ip.split('/')
		split_ip = ipaddress.IPv4Network(u'{}'.format("{}/{}".format(ipaddr, IPAddress(netmask).netmask_bits())))
		return tuple([str(split_ip[0]), str(split_ip[-1])])
	
def clean_ip_range(ip):
	try:
		return SRC_MAP[ip]
	except KeyError:
		split_ip = ip.split('-')
		return tuple([str(split_ip[0]), str(split_ip[1])])
def clean_port(port):
	try:
		return PRT_MAP[port]
	except KeyError:
		split_port = [int(x) for x in port.split(':')]
		if len(split_port) == 1:
			split_port.append(int(split_port[0]))
		return tuple(split_port)

		
def print_rule_objects(obj_list):
	for obj in obj_list:
		print("===========================")
		print(obj)
	#for obj in obj_list:

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
#	objList = TupleList()
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
					# objList.list.append(rule_obj)	

def main():	
	objList = extract(iptc.Table(iptc.Table.FILTER))
	print_rule_objects(RULE_OBJ_LIST)
if __name__ == "__main__":
	main()







