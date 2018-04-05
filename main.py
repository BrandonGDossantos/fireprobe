import iptc

class tupleList(object):
	def __init__(self):
		self.list = []

class ruleTuple(object):
	def __init__(self):
		self.list = []

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
		if obj.protocol == 'tcp':
			obj.protocol = [6,6]

		elif obj.protocol == 'udp':
			obj.protocol = [17,17]

		if obj.src_range == '0.0.0.0/0.0.0.0':
			obj.src_range = [0,255]

		if obj.dst_range == '0.0.0.0/0.0.0.0':
			obj.dst_range = [0,255]

		if obj.src == '0.0.0.0/0.0.0.0':
			obj.src = [0,255]

		if obj.dst == '0.0.0.0/0.0.0.0':
			obj.dst = [0,255]

		if obj.sport == 'None':
			obj.sport = [0,65535]

		if obj.dport == 'None':
			obj.dport = [0,65535]

		if obj.action == 'ACCEPT':
			obj.action = 0

		elif obj.action == 'DROP':
			obj.action = 1 
	
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
		# print(obj.list)
		# print("\n")
	return t

def printTupList(t):
	for obj in t.list:
		print(obj.__dict__)
		print("\n")
def extract(table):
	x = 1	
	t = tupleList()
	for chain in table.chains:
		for rule in chain.rules:
			# print("======================RULE {0} IN CHAIN=============================".format(x))
			# print("\n")
			x+=1
			r = ruleTuple()
			y = 0
			for match in rule.matches:
				y+=1 
				
				# print("----------------------------{}------------------------------".format("Match"))
				r.fill(str(rule.protocol), str(rule.src), str(rule.dst), str(match.src_range), str(match.dst_range), str(match.sport), str(match.dport), str(rule.target.name)) 
				#noNoneDict = {k:v for k, v in vars(r).items() if v != 'None'}

				noNoneDict = {k:v for k, v in vars(r).items()}
				r.list.append(noNoneDict)
				if y == len(rule.matches):
					t.list.append(r)		
				# print("\n")
	clean(merge_two_dicts(t))
	
	printTupList(t)			


def main():	
	extract(iptc.Table(iptc.Table.FILTER))
if __name__ == "__main__":
	main()







