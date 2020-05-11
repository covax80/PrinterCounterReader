#!/usr/bin/env python3
# coding: cp1251

import unittest
import random




#from cnt_reader import *

from cnt_reader import tcpping

class TcppingTestCase(unittest.TestCase):
  	def test_localhost_connection(self):
  		test_host = ('127.0.0.1',445)
  		waiting_test_result = True
  		self.assertTrue(waiting_test_result == tcpping(*test_host), "tcpping function returns incorrent value.") 
  

