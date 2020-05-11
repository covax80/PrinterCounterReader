#!/usr/bin/env python3
#-*- coding: utf-8 -*-
# Script for scan printers in several subnets (from filials.ini file)



import os,sys
from time import time
if len(sys.argv) < 2:
	f = open('filials.ini').readlines()
else:
	f = open(sys.argv[1]).readlines()

#data = {}

# ---- UTILS part
def split_strip(comma_separated_txt="", delimiter=","):
	return [x.strip() for x in comma_separated_txt.split(delimiter)]



#os.chdir(os.path.dirname(__file__))
print(os.getcwd())
res 		= None
filial 		= None
ip_range 	= None
t0 			= time()
t1 			= None
for string in f:
	if string.strip() == "":
		continue
	res = split_strip(string,'\t')
	#print(locals())
	filial 		= res[0]
	ip_range 	= res[1] + '/21'
	#data[res[0]] = res[1]
	t1 = time()	
	os.system('python.exe ./cnt_reader.py -M html -S True -T 128 -L %(ip_range)s -P model_snmp_oid,share_login_snmp_oid,share_password_snmp_oid,status_1_snmp_oid,status_2_snmp_oid,last_doc_snmp_oid -F Rep_%(filial)s'%locals())
	#os.system('python.exe ./cnt_reader.py -M html -S True -T 128 -L %(ip_range)s -P network_snmp_oid,model_snmp_oid,status_1_snmp_oid,status_2_snmp_oid,last_doc_snmp_oid -F Rep_%(filial)s'%locals())
	#print('python.exe cnt_reader.py -M html -S True -T 128 -L %(ip_range)s -P model_snmp_oid,share_login_snmp_oid,share_password_snmp_oid,status_1_snmp_oid,status_2_snmp_oid,last_doc_snmp_oid -F Rep_%(filial)s'%locals())
	delta_t = time() - t1
	print("Filial %(filial)s scanned - %(delta_t).2f sec "%locals())
	
print("PROCCESS FINISHED - %.2f sec."%(time() - t0))
