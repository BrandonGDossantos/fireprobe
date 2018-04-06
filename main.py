import iptc
from netaddr import IPAddress
import ipaddress

class tupleList(object):
	def __init__(self):
		self.list = []
		self.tup = ()
class ruleTuple(object):
	def __init__(self):
		self.list = []
		self.tup = ()
	def fill(self, protocol, src, dst, src_range, dst_range, sport, dport, action):
		self.protocol = protocol
		self.src_range = src_range
		self.dst_range = dst_range
		self.src = src
		self.dst = dst
		self.sport = sport
		self.dport = dport
		self.action = action

def clean(t):
	for obj in t.list:
		obj.list = []
		# dictionary for this
		if obj.protocol == 'tcp':
			obj.protocol = (6,6)
			obj.list.append(obj.protocol)
		elif obj.protocol == 'udp':
			obj.protocol = (17,17)
			obj.list.append(obj.protocol)
		if obj.src_range == 'None':
			obj.src_range = ('0.0.0.0','255.255.255.255')
			obj.list.append(obj.src_range)
		else:
			obj.src_range = tuple(obj.src_range.split('-'))
			obj.list.append(obj.src_range)
		if obj.dst_range == 'None':
			obj.dst_range = ('0.0.0.0','255.255.255.255')
			obj.list.append(obj.dst_range)
		else:
			obj.dst_range = tuple(obj.dst_range.split('-'))
			obj.list.append(obj.dst_range)
		if obj.src == '0.0.0.0/0.0.0.0':
			obj.src = ('0.0.0.0','255.255.255.255')
			obj.list.append(obj.src)
		else:
			ip, netmask = obj.src.split('/')
			n = ipaddress.IPv4Network(u'{}'.format("{}/{}".format(ip, IPAddress(netmask).netmask_bits())))
			obj.src = tuple([str(n[0]), str(n[-1])])
			obj.list.append(obj.src)
		if obj.dst == '0.0.0.0/0.0.0.0':
			obj.dst = ('0.0.0.0','255.255.255.255')
			obj.list.append(obj.dst)
		else:
			ip, netmask = obj.src.split('/')
			n = ipaddress.IPv4Network(u'{}'.format("{}/{}".format(ip, IPAddress(netmask).netmask_bits())))
			obj.src = tuple([str(n[0]), str(n[-1])])
			obj.list.append(obj.src)
		if obj.sport == 'None':
			obj.sport = (0,65535)
			obj.list.append(obj.sport)
		else:
			b = obj.dport.split(':')
			if len(b) == 1:
				b.append(b[0])
			obj.dport = tuple(b)
		if obj.dport == 'None':
			obj.dport = (0,65535)
			obj.list.append(obj.dport)
		else:
			print(obj.dport)
			b = obj.dport.split(':')
			if len(b) == 1:
				b.append(b[0])
			obj.dport = tuple(b)
			obj.list.append(obj.dport)
		if obj.action == 'ACCEPT':
			obj.action = 0
			obj.list.append(obj.action)
		elif obj.action == 'DROP':
			obj.action = 1 
			obj.list.append(obj.action)
		obj.tup = tuple(obj.list)
	
def merge_two_dicts(t):
	for obj in t.list:
		if len(obj.list) == 2:
			x = obj.list[0]
			y = obj.list[1]
			z = dict(x.items()+y.items())
			del z['list']
			obj.list = z
		else:
			del obj.list[0]['list'] 
			obj.list = obj.list[0]	
	return t

def printTupList(t):
	for obj in t.list:
		print(obj.tup)
		print("\n")
def extract(table):
	objList = tupleList()
	for chain in table.chains:
		for rule in chain.rules:
			r = ruleTuple()
			y = 0
			for match in rule.matches:
				y+=1 
				r.fill(str(rule.protocol), str(rule.src), str(rule.dst), str(match.src_range), str(match.dst_range), str(match.sport), str(match.dport), str(rule.target.name)) 
				#noNoneDict = {k:v for k, v in vars(r).items() if v != 'None'}

				noNoneDict = {k:v for k, v in vars(r).items()}
				r.list.append(noNoneDict)
				if y == len(rule.matches):
					objList.list.append(r)		
				# print("\n")
	clean(merge_two_dicts(objList))	
	printTupList(objList)			


def main():	
	n = ipaddress.IPv4Network(u'10.10.128.0/24')
	first, last = n[0], n[-1]
	# print(first, last)
	extract(iptc.Table(iptc.Table.FILTER))

if __name__ == "__main__":
	main()







