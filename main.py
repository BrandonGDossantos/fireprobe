import iptc

class ruleTuple(object):
	def __init__(self, protocol, single_src, single_dst, range_src, range_dst, sport, dport, action):
		self.protocol = protocol
		self.single_src = single_src
		self.single_dst = single_dst
		self.range_src = range_src
		self.range_dst = range_dst
		self.sport = sport
		self.dport = dport
		self.action = action




def printTupList(ruleTuple):
	#print(ruleTuple.tupList)
	r = {k:v for k, v in vars(ruleTuple).items() if v != 'None'}
	print(r)
	z = {**	
	#print ', '.join("%s: %s" % item for item in r.items())
def extract(table):
	x = 1	
	for chain in table.chains:
		for rule in chain.rules:
			print("======================RULE {0} IN CHAIN=============================".format(x))
			print("\n")
			x+=1
			for match in rule.matches:
				print("----------------------------{}------------------------------".format("Match"))
				r = ruleTuple(str(rule.protocol), str(rule.src), str(rule.dst), str(match.src_range), str(match.dst_range), str(match.sport), str(match.dport), str(rule.target.name)) 
				#print(r.__dict__)
				#r.tupList.append(r.__dict__)	
				printTupList(r)
				print("\n")
			


def main():	
	extract(iptc.Table(iptc.Table.FILTER))
if __name__ == "__main__":
	main()







