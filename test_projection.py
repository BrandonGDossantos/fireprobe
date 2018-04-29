import unittest
from core import projection, end_points, cartesian, launch_probes, clean_resolved_witness, alert_user

class TestProjectionMethods(unittest.TestCase):
	def test_print(self):
		PROPERTY_RULE = {'src':(23,87), 'dst':(73,177), 'action':(0,0)}
		FIREWALL_RULE = [{'src':(10,110), 'dst':(90,190), 'action':(0,0)}, 
					{'src':(20,120), 'dst':(80,180), 'action':(1,1)}, 
					{'src':(30,130), 'dst':(70,170), 'action':(0,0)},
					{'src':(40,140), 'dst':(60,160), 'action':(1,1)},
					{'src':(1,200), 'dst':(1,200), 'action':(0,0)},
					{'src':(1,20), 'dst':(180,200), 'action':(1,1)}]
		clean_projected_firewall = projection(PROPERTY_RULE, FIREWALL_RULE)
		

	def test_end_points(self):
		PROPERTY_RULE1 = {'src':(23,87), 'dst':(73,177), 'action':(0,0)}
		FIREWALL_RULE1 = [{'src':(10,110), 'dst':(90,190), 'action':(0,0)}, 
					{'src':(20,120), 'dst':(80,180), 'action':(1,1)}, 
					{'src':(30,130), 'dst':(70,170), 'action':(0,0)},
					{'src':(40,140), 'dst':(60,160), 'action':(1,1)},
					{'src':(1,200), 'dst':(1,200), 'action':(0,0)}]
		PROPERTY_RULE2 = {'src':(1,100), 'dst':(1,100), 'action':(0,0)}
		CLEAN_PROJECTION1 = [{'action': 0, 'src': (23, 87), 'dst': (90, 177)}, 
							{'action': 1, 'src': (23, 87), 'dst': (80, 177)}, 
							{'action': 0, 'src': (30, 87), 'dst': (73, 170)}, 
							{'action': 1, 'src': (40, 87), 'dst': (73, 160)}, 
							{'action': 0, 'src': (23, 87), 'dst': (73, 177)}]
		CLEAN_PROJECTION2 = [{'action': 0, 'src': (1, 10), 'dst': (1, 10)}, {'action': 1, 'src': (1, 100), 'dst': (1, 100)}]
		end_points_list = end_points(PROPERTY_RULE1, CLEAN_PROJECTION1)
		witness = list(cartesian(end_points_list))
		resolved_witness = launch_probes(witness, FIREWALL_RULE1)	
		least_witness = clean_resolved_witness(resolved_witness, witness, PROPERTY_RULE1['action'][0])
		alert_user(least_witness)


if __name__ == '__main__':
	unittest.main()
	
