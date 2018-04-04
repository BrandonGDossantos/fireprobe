import iptc

table = iptc.Table(iptc.Table.FILTER)
for chain in table.chains:
	x = 1	
	for rule in chain.rules:
		print("======================RULE {} IN CHAIN=============================".format(x))
		print("[]Proto: {}".format(rule.protocol))
		print("[]Src: {}".format(rule.src))
		print("[]Dst: {}".format(rule.dst))
		print("In Interface: {}".format(rule.in_interface))
		print("Out Interface: {}".format(rule.out_interface))
		x+=1
		for match in rule.matches:
			print("\t\t\t======================MATCH IN RULE=============================")
			print("\t\t\t[]Dst port: {}".format(match.dport))
			print("\t\t\t[]Src port: {}".format(match.srcport))
			print("\t\t\tMatch src_range: {}".format(match.src_range))
			print("\t\t\tMatch dst_range: {}".format(match.dst_range))
			print("\t\t\tMatch name: {}".format(match.name))
			print("\t\t\tRule Target Name: {}".format(rule.target.name))

