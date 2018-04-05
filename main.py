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

def main():	
	table = iptc.Table(iptc.Table.FILTER)
	x = 1	
	for chain in table.chains:
		for rule in chain.rules:
			print("======================RULE {0} IN CHAIN=============================".format(x))
			print("\n")
			x+=1
			for match in rule.matches:
				print("----------------------------{}------------------------------".format("Match"))
				# print("[Protocol] Proto: {}".format(rule.protocol))
				# print("[Single Source Address] Src: {}".format(rule.src))
				# print("[Single Destination Address] Dst: {}".format(rule.dst))
				# print("Chain Name: {}".format(chain.name))
				# print("[Destination Port] Dst port: {}".format(match.dport))
				# print("[Source Port] Src port: {}".format(match.sport))
				# print("[Range Source Address] Match src_range: {}".format(match.src_range))
				# print("[Range Destination Address] Match dst_range: {}".format(match.dst_range))
				# print("[Action] Rule Target Name: {}".format(rule.target.name))
				r = ruleTuple(str(rule.protocol), str(rule.src), str(rule.dst), str(match.src_range), str(match.dst_range), str(match.sport), str(match.dport), str(rule.target.name)) 
				print(r.__dict__)
				print("\n")
				
if __name__ == "__main__":
	main()







