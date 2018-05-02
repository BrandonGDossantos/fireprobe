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
	"""The class is the structure for each rules in the firewall and the property
	
	Attributes: 
		protocol: tcp, udp that gets converted to a number by the PROTO_MAP
		src: source address that is formatted '0.0.0.0/0'
		dst: destination address formatted '0.0.0.0/0'
		sport: source port formatted '22' or '22:33' as a range
		dport: destination port 
		action: ACCEPT or DROP mapped to 0 or 1 respectively
		srcRange: range of source IPs 
		dstRange: range of destination IPs
	"""
	def __init__(self, protocol=None, src=None, dst=None, sport=None, dport=None, action=None, srcRange=None, dstRange=None):
		"""Initializes the object with the passed in values otherwise defaulted to None."""
		self.set_protocol(protocol)
		self.set_pairs(src, srcRange, sport, dst, dstRange, dport)
		self.set_action(action)
	def set_protocol(self, protocol):
		"""
		Creates a tuple version of the protocol using PROTO_MAP.
		Ex. protocol 'tcp' converts to (6,6)
		"""
		self.protocol = (PROTO_MAP[protocol], PROTO_MAP[protocol])
	# Destinguishes whether the user inputed a range of IPs or not.
	def set_pairs(self, src, srcRange, sport, dst, dstRange, dport):
		"""Destinguishes whether the user inputed a range of IPs or a single IP and sets attributes"""
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
		"""
		Sets the action using ACTION_MAP
		Ex. 'ACCEPT' converts to (0,0) 
		"""
		self.action = ACTION_MAP[action]

def set_ip(ip):
	"""Sets the class src/dst attribute if its a single ip.
	
	Sets the ip tuple to the default (0, 4294967295) value if the passed in ip value is '0.0.0.0/0', None, or 'None'/
	Otherwise parse the single CIDR ip into a range of integer ips.
	
	Args: 
		ip: a single CIDR ip.
	
	Retuns:
		A tuple that represents the range of ips. 
		For example: 192.168.1.0/24 is actually (192.168.1.0-192.168.1.255) then converted to integer as (3232235776, 3232236031).
					 192.168.1.25/32 is actually (192.168.1.25-192.168.1.25) then converted to integer as (3232235801, 3232235801).
	"""
	if ip in IP_MAP:
		return IP_MAP[ip]
	else:
		# The ip comes in as 192.168.1.0/255.255.255.0, so we need to interpret this as CIDR
		ipaddr, netmask = ip.split('/')
		# Use python ipaddress library to convert the mask to bits (255.255.255.0 -> 24)
		# The ip will now be 192.168.1.0/24
		# Split_ip is a list of all possible values within the range
		split_ip = ipaddress.IPv4Network(u'{}'.format("{}/{}".format(ipaddr, IPAddress(netmask).netmask_bits())))
		# Create a tuple where the left value is the first ip in the range and the right value is the highest value 
		return tuple([int(IPAddress(str(split_ip[0]))), int(IPAddress(str(split_ip[-1])))])

def set_ip_range(ip):
	"""Sets the class single src/dst attribute if its a range
	
	Args: 
		ip: a range interpreation

	Returns:
		A tuple that represents the range of ips. 
	"""
	if ip in IP_MAP:
		return IP_MAP[ip]
	# The ip comes in as 192.168.1.23-192.168.1.33, so we need to just convert their ips to integer since
	# a beginning and end of the range is inputed.  
	else:
		split_ip = ip.split('-')
		return tuple([int(IPAddress(str(split_ip[0]))), int(IPAddress(str(split_ip[1])))])

def set_port(port):
	"""Sets the class port attribute 

	Args: 
		port: the src/dst port
	
	Returns:
		A tuple that represents the range of ports.
	"""
	# Return default if port is None
	if port in PRT_MAP:
		return PRT_MAP[port]
	# Splits the port at ':'.
	# This will split the port into two values or if there
	# is no range inputed, it will detect that there is not pair 
	# and return the tuple.
	else: 
		split_port = [int(x) for x in port.split(':')] # Makes a list of min and max port.
		# 22:33 = [22, 33]
		# 33 = [33,]
		# Checks whether there is 1 or 2 elements present.
		if len(split_port) == 1: # [33,]
			split_port.append(int(split_port[0])) # [33,] -> [33, 33]
		return tuple(split_port)
		
def projection(property_rule, firewall_rules):
	"""Project the firewall rules over the property to filter what we don't care about
	
	Args: 
		property_rule: property Rule object
		firewall_rules: list of dictionary versions of the Rule object

	Returns:
		A list of new firewall rules that were projected upon
	"""
	projected_firewall = []
	for firewall_rule in firewall_rules:
		# Create a clean dictionary that will hold the new projected rule
		projected_rule = {}
		# Iterate through each key in the rule to commence projection on values
		for k in firewall_rule.keys():
			# Call the function check_overlaps to find where the property and the firewall values overlap
			projected_rule[k] = check_overlaps(firewall_rule, property_rule, k)
		# Add the new projected rule to the projected firewall list
		projected_firewall.append(projected_rule)
	# Before we return the new projected firewall, lets clean up any rules that had non-overlapping values.
	return clean_projections(projected_firewall)

def check_overlaps(firewall_rule, property_rule, k):
	"""This is the algorithm that will logicaly create new values if there is indeed an overlap

	Args:
		firewall_rule: the rule in the firewall we are projecting onto
		property_rule: the property rule we are projecting
		k: the field name, 'src', 'dst', 'sport'...

	Returns:
		The new value for the field that has correct projection values
	"""
	# if were attempting to project with the 'action' field,
	# just set it to the firewall's 'action' value. 
	if k == 'action':
		return firewall_rule[k][0]
	# if the firewall's max value is less than the property's min, we're out of bounds
	# if the the firewall's min value is greater than the property's max, we're out of bounds
	if (firewall_rule[k][1] < property_rule[k][0]) or (firewall_rule[k][0] > property_rule[k][1]):
		return None
	else:
		# if the property's min value is greater than the firwall's min, return the property min
		if property_rule[k][0] > firewall_rule[k][0]:
			left = property_rule[k][0]
		else:
			# else return the firewall's min
			left = firewall_rule[k][0]
		# if the property's max value is greater than the firewall's max, return the firewall max
		if property_rule[k][1] > firewall_rule[k][1]:
			right = firewall_rule[k][1]
		else:
			# else return the property's max
			right = property_rule[k][1]
	return tuple([left, right])

def clean_projections(PROJECTED_FIREWALL):
	"""Removes projected rules that have 'None' values to reinforce that we need overlap in each field
	
	Args: 
		PROJECTED_FIREWALL: The global constant that holds all the new projected firewall
	
	Returns:
		A projected firewall with no invalid rules that contain 'None'
	"""
	clean_projected_firewall = []
	for rule in PROJECTED_FIREWALL:
		if None not in rule.values():
			clean_projected_firewall.append(rule)
	return clean_projected_firewall

def end_points(property_rule, projected_firewall):
	"""Discover possible end points for each field
	
	Args: 
		property_rule: the property rule
		projected_firewall: the projected firewall list
	
	"""
	end_points = {} # {'src': [33, 40. 80], 'dst': [75, 100, 90]}
	property_action = property_rule['action'][0] # grab the property's action value
	for rule in projected_firewall:
		# run this algorithm if the rule and property are friendly, determined by the action value, 0 and 0.
		if rule['action'] == property_action:
			# iterate through all fields in the rule
			for k in rule.keys():
				# work on getting the endpoints for each field BUT the action field
				if k != 'action':
					# Add the (rule's max value +1) value as an end point only if its less than the property's max
					if (rule[k][1]+1) <= property_rule[k][1]: # if (rule max value +1) <= (property max)
						end_points.setdefault(k, []).append((rule[k][1])+1)
		# if the rule and property are enemies, 0 and 1. 
		else:
			for k in rule.keys():
				if k != 'action':
					# Add the (rule's min value) as an end point
					end_points.setdefault(k, []).append(rule[k][0])
	# Before we pass this endpoint dictionary, lets remove any duplicates to ensure our cartesian is clean
	return remove_duplicates(end_points)

def cartesian(end_point_list):
	"""Produce the cartesian product of end points in order to get possible probes

	Args: 
		end_point_list: list of dictionary structures packets
	
	Returns:
		Complicated one liner that produces the cartesian product
	"""
	return (dict(zip(end_point_list, x)) for x in itertools.product(*end_point_list.values()))

def remove_duplicates(end_points):
	"""The end point values can have duplicates, but we don't want them. 
	   So we use a set to remove duplicates from the field values
	
	Args:
		end_points: dictionary with key as field and value as list of possible end points
	
	Return: 
		removed_duplicates: A clean dictionary with key as field and value 
		as list of possible end points, without duplicates
	"""
	removed_duplicates = {}
	for k in end_points.keys():
		# first turn the old list into a set, thus removing duplicates, 
		# then turn it back into a list
		removed_duplicates[k] = list(set(end_points[k]))
	return removed_duplicates

def launch_probes(witness_packets, RULE_OBJ_LIST):
	"""This will mimic packets going through the firewall.
	
	Args:
		witness_packets: list of probes
		RULE_OBJ_LIST: global constant that holds original firewall rules

	Returns:
		A dictionary where the key is the index of the firewall rule within the RULE_OBJ_LIST 
		and the value as the 'action' that was resolved while passing it through the firewall
		{[index]:[action], 0:0, 1:0, 2:1, 3:1, 4:1, 5:0, 6:0}
	"""
	resolved_witness = {}
	for packet in witness_packets:
		for rule in RULE_OBJ_LIST:
			# this boolean is set to make sure only the first decision on how the packet is treated is considered
			dont_add = False
			for k in packet.keys():
				# check if the probe field value is within the firewall rule's value range
				# if so, proceed to check the next field and so on,
				# until all fields are checked, then the packet it fully resolved 
				if (packet[k] - rule[k][0]) >= 0 and (packet[k] - rule[k][1] < 0):
					pass
				else:
					dont_add = True
					break
			# hit this when the packet is fully resolved and we have a decision on what to do with the packet (ACCEPT or DROP).
			# this check is to make sure we are working with the first resolution, not all resolutions of the packet.
			# There can be multiple resolutions of a packet in a firewall, the first resolution is what we care about...
			if not dont_add:
				# Get the index of the packet that is resolved
				index_packet = witness_packets.index(packet)
				# Check if we already processed the packet
				if resolved_witness.has_key(index_packet):
					continue
				# This is the first time seeing it so we add a index as key and the value as the resolved decision (0 or 1).
				else:
					resolved_witness[index_packet] = rule['action'][0]
	return resolved_witness

def clean_resolved_witness(resolved_witness, witness_packets, property_action):
	"""This will remove any packets that are friendly to the property.
	   We do this because we only want packets that are enemies and pass through the firewall
	
	Args: 
		resolved_witness: the list of dictionary probe packets that were resolved, [{'src':40, 'dst', 23}, ...]
		witness_packets: the dictionary of that holds the index of the resolved packet and the decision, {0:1, 1:0, 2:0, 3:1, 4:0, 5:0}
		property_action: the action value of the property

	Returns:
		list of least witness packets
	"""
	least_witness = []
	for k,v in resolved_witness.items():
		if v != property_action:
			least_witness.append(witness_packets[k])		
	return least_witness

def alert_user(least_witness):
	"""Alert the user on whether or not there is a leak in the firewall
	
	Args: 
		least_witness: list of least witness packets
	"""
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
	"""Extract all rules from iptables using python iptables library and create Rule objects out of them
	   then append each object to the global RULE_OBJ_LIST for later consumption.
	
	Args: 
		table: iptables
	"""
	for chain in table.chains:
		for rule in chain.rules:
			# Initialize the rule oject for each rule
			rule_obj = Rule()
			y = 0
			for match in rule.matches:
				y+=1
				# set the protocol
				rule_obj.set_protocol(str(rule.protocol))		
				# set the src, dst, sport, dport, srcRange, dstRange
				rule_obj.set_pairs(str(rule.src), str(match.src_range), str(match.sport), str(rule.dst), str(match.dst_range), str(match.dport))
				# set the action
				rule_obj.set_action(str(rule.target.name))
				# There can be multiple matches for a rule if there is an ip range involved, this will account for it
				if y == len(rule.matches):
					RULE_OBJ_LIST.append(rule_obj.__dict__)

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
	# Initialize the property rule from user input
	property_rule = Rule(args.protocol, args.src, args.dst, args.sport, args.dport, args.action, args.srcRange, args.dstRange)
	# Extract the iptables firewall to RULE_OBJ_LIST
	extract(iptc.Table(iptc.Table.FILTER))
	# Project
	projected_firewall = projection(property_rule.__dict__, RULE_OBJ_LIST)
	# Get end points
	end_point_list = end_points(property_rule.__dict__, projected_firewall)
	# Produce cartesian
	witness_packets = list(cartesian(end_point_list))
	# Get resolved probes
	resolved_witness = launch_probes(witness_packets, RULE_OBJ_LIST)
	# Filter out probes that are friendly to property
	least_witness = clean_resolved_witness(resolved_witness, witness_packets, property_rule.action)
	# Alert the user with results
	alert_user(least_witness)
if __name__ == "__main__":
	main()
