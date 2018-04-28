import unittest
from core import projection, end_points

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
		print(clean_projected_firewall)
		

	def test_end_points(self):
		PROPERTY_RULE = {'src':(23,87), 'dst':(73,177), 'action':(0,0)}
		CLEAN_PROJECTION = [{'action': 0, 'src': (23, 87), 'dst': (90, 177)}, {'action': 1, 'src': (23, 87), 'dst': (80, 177)}, {'action': 0, 'src': (30, 87), 'dst': (73, 170)}, {'action': 1, 'src': (40, 87), 'dst': (73, 160)}, {'action': 0, 'src': (23, 87), 'dst': (73, 177)}]
		end_points(PROPERTY_RULE, CLEAN_PROJECTION)
		


if __name__ == '__main__':
	unittest.main()
	
