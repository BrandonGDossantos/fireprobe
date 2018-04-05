import iptc

class ruleTuple(object):
	def __init__(self, protocol, single_src, single_dst, range_src, range_dst, sport, dport, action):
		self.protocol = protocol
		self.single_src = single_src
		self.single_dst = single_dst
		self.sport = sport
		self.dport = dport
		self.action = action

def main():	
	table = iptc.Table(iptc.Table.FILTER)
	x = 1	
	for chain in table.chains:
		for rule in chain.rules:
			print("======================RULE {0} IN CHAIN=============================".format(x))
			# protocol = rule.protocol
			# single_src = rule.src
			# single_dst = rule.dst
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

				if rule.protocol:
					print("Protocol", str(rule.protocol))
				if rule.src != "0.0.0.0/0.0.0.0":
					print("Src", str(rule.src))
				if rule.dst != "0.0.0.0/0.0.0.0":
					print("Dst",str(rule.dst))
				if match.dport:
					print("Dport", str(match.dport))
				if match.sport:
					print("Sport", str(match.sport))
				if match.src_range:
					print("Src_range", str(match.src_range))
				if match.dst_range:
					print("Dst_range", str(match.dst_range))
				if rule.target.name:
					print("Action", str(rule.target.name))		


if __name__ == "__main__":
	main()







