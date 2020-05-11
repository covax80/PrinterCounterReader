#!/usr/bin/env python3
# coding: cp1251


#----------------------------------------------------------------------
# Description: SNMP printer statistic collector
# Author:  Artyom Breus <Artyom.Breus@gmail.com>
# Created at: Thu Jul 21 17:02:07 VLAT 2014
# Computer: vostok-ws060.slavyanka.local#
# Copyright (c) 2014 Artyom Breus  All rights reserved.
#
#----------------------------------------------------------------------




"""
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""



from datetime import datetime, timedelta
from pprint import pprint as pp
from os import path as os_path
import sys
import re
import ipaddress

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString


import socket
import logging

from multiprocessing.dummy import Pool as ThreadPool
from time import time
#-------




#Globals
global path,signatures,data,data_headers,THREADS
path 			= os_path.dirname(os_path.abspath(__file__))
signatures 		= {}
data 			= {}
data_headers	= {}
THREADS			= None

 
# create logger with 'cnt_printer'
logger = logging.getLogger('cnt_reader')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('cnt_reader.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)
"""
class L:
	def info(self,txt):
		pp(txt)

logger = L()
"""
#Exit codes
# 0 - OK
# 1 - Config Error
# 2 - Debug



# ConfigParser import Block 
from configparser import ConfigParser
config = ConfigParser()
# Если была установка через nsis то конфиг ищется в другой диреткории
#if path[-4:] == 'pkgs':
#	config.read(path + '/../settings.ini')
#else:
config.read(path + '/settings.ini')

#logger.info(path[-4:])
#sys.exit(1)

# OptParser import Block
from optparse import OptionParser
parser = OptionParser(add_help_option=False)

#Options
options = {}

#Utils Block
def split_strip(comma_separated_txt="", delimiter=","):
	return [x.strip().upper() for x in comma_separated_txt.split(delimiter)]
	

def tcpping(host,port):
	"""Возвращает True если host имеет открытый port"""
	rs=True
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)
	try:
		s.connect((host,port))
		s.close()
	except socket.timeout:
		s.close()
		rs=False
	except socket.error:
		s.close()
		rs=False
	return rs

def gethostbyaddr(ipv4):
	""" Возвращает "hostname и IP-шник" получая IP-шник"""
	try:
		hst = socket.gethostbyaddr(ipv4)
	except socket.herror:
		hst = ("* ",[],[ipv4])	
	res = dict(zip(('hostname','alias_list','ip'),hst))
	return "%(hostname)s %(ip)s"%res


def set_true_ip(hostname):
	""" Резолвим IP из hostname """
	ip = hostname
	its_ip = True # ?
	try:
		its_ip = socket.inet_aton(hostname)
	except OSError:
		logger.info("set_true_ip Error:" + str(sys.exc_info()))
		its_ip = False

	# If address is not IPv4 then dns resolv it
	#logger.info(ip)
	if not its_ip:
		try:
			ip = socket.gethostbyname(hostname)
		except socket.gaierror:
			return False
	return ip

def to_boolean(mean):
	BOOLEAN_STATES = {'1': True, 'yes': True, 'true': True, 'on': True,
                      '0': False, 'no': False, 'false': False, 'off': False}
	try:
		return BOOLEAN_STATES[mean.lower()]
	except IndexError:
		return False


#Scan mode block
def make_signatures_list():	 
	"""
	Анализирует подразделы 'signature' в settings.ini и создаёт словарь signatures[section] = value
	Функция нужна для режима сканирования - к какому классу относится то или инное устройство

	"""
	for section, means_dictionary in config.items():
		for opt, value in means_dictionary.items():
			if opt == 'signature':
				signatures[section] = value
	return


def check_model(*args):
	"""
	Функция получает адрес к опросу 	   
	Возвращает tuple(результат_опроса, host, signature_and_address)
	"""

	printer_alias, ip = args[0]

	global config
	# ping-уем адрес на 515 порту (принтер ли он) 
	# TODO:  возможно надо заменить на просто icmp-ping	
	if tcpping(ip, 515):		
		model = get_snmp_mean(ip, '1.3.6.1.2.1.25.3.2.1.3.1')
		logger.info("< SCAN MODE: ANALISING [%s (%s)] -> %s"%(printer_alias,ip,model))
		if model:
			try:			
				alias_from_signature = [pr_alias for pr_alias,sig in signatures.items() if sig in model][0]
				logger.info("< SCAN MODE: MATCHES ARE FOUND  [%s] > "%alias_from_signature)
			except IndexError:
				alias_from_signature = None

			if alias_from_signature:
				host = gethostbyaddr(printer_alias)
				signature_and_address   = alias_from_signature + ";" + ip
				config['Aliases'][host] = alias_from_signature + ";" + ip				
			else:
				logger.info('The model of printer %s (host - %s) not supported'%(gethostbyaddr(printer_alias),ip))
				return (False, None, None)
		else:
			logger.debug('No snmp model data for %s. Remove him from monitoring_list'%printer_alias)
			return (False, None, None)	
	else:			
		logger.debug('Have not access to printer %s. Remove him from monitoring_list'%printer_alias)
		return (False, None, None)
	# return (True,"vostok-pr02 [172.21.0.202]")
	return (True, host, signature_and_address)


def add_extra_options():
	global config
	netaddresses = {}
	ip = None
	
	# make dictionary from config - {'printer_alias':'search_signature',...,'hp1120':'1120'}
	make_signatures_list()

	# находим истинные адреса устройств который можно опрашивать
	monitoring_list = split_strip(config['Main']['monitoring_list'])
	new_monitoring_list = []
	list_for_check_model = []
	
	for printer_alias in monitoring_list:
		if not '.' in printer_alias:
			netaddresses[printer_alias] = printer_alias + '.' + config['Main']['domain']							
		else:
			netaddresses[printer_alias] = printer_alias
		
		ip = set_true_ip(netaddresses[printer_alias])
		if not ip:
			logger.info('DNS server can\'t resolve host %s'%netaddresses[printer_alias])
			continue
		
		list_for_check_model.append( (printer_alias, ip) )
	logger.debug('THREADS [%d]'% THREADS)
	pool = ThreadPool(THREADS)		
	res  = pool.map(check_model, list_for_check_model)	

	for response, host, signature_and_address in res:
		if response is True:
			new_monitoring_list.append(host)	
			config['Aliases'][host] = signature_and_address

	# формирем новый config['Main']['monitoring_list']  без прининтеров у которых не распознались сигнатуры	
	config['Main']['monitoring_list'] = ",".join(new_monitoring_list)
	logger.info('< SCAN MODE: new request list [%s] '% config['Main']['monitoring_list'])
	return 


#Configs parser Block

# Main Block
def get_opt_parser(called_from_module = False):	
	"""Add options from optparser to configparser options"""	

	parser.add_option("-M", "--mode", dest="mode",
			help="Programm mode: 'html', 'plaintext','plaintable','sql', 'Tk', 'csv'", metavar="MODE", default=None)
	parser.add_option("-S", "--scan_mode", dest="scan_mode",
                    help="It's try to detect printer model via snmp codes", metavar="BOOLEAN", default=None)
	parser.add_option("-L", "--monitoring_list", dest="monitoring_list",
                    help="List of printer aliases for monitoring. Example: vostok-pr11, vostok-pr12", metavar="LIST_OF_ALIASES", default=None)
	parser.add_option("-E", "--extended_list", dest="extended_list",
                    help="List of printers for monitoring. Example: 'vostok-pr11;hp1120;172.21.0.212, vostok-pr12;kyocera3920;172.21.0.211'", 
                    metavar="LIST", default=None)
	parser.add_option("-F", "--file_name_preffix", dest="file_name_preffix",
                    help="Name of output file", metavar="FILE_PREFFIX", default=None)
	parser.add_option("-P", "--values_for_reading", dest="values_for_reading",
                    help="Params for reading. E.g.: model_snmp_oid, network_snmp_oid, pagecounter_snmp_oid", metavar="PARAM_snmp_oid", default=None)
	parser.add_option("-I", "--pipe", dest="pipe_import",
                    help="import printer list from pipe", metavar="BOOLEAN", default=None)
	parser.add_option("-H", "--header", dest="header",
                    help="Enable/disable header in outputs data", metavar="BOOLEAN", default=None)
	parser.add_option("", "--runtime", dest="runtime",
                    help="Print runtime", metavar="BOOLEAN", default=None)
	parser.add_option("-T", "--threads", dest="threads",
                    help="Print runtime", metavar="INTEGER", default=None)

	args = None
	(opt, args) = parser.parse_args(args)

	#pp(opt)

	#if opt.mode or called_from_module:
	if opt.mode:
		config['Main']['mode'] = str(opt.mode)
	else:
		parser.print_help()
		sys.exit(0)

	
	if opt.monitoring_list:
		if '/' in opt.monitoring_list:
			opt.monitoring_list = ",".join([str(ipaddr) for ipaddr in ipaddress.IPv4Network(opt.monitoring_list)])
		config['Main']['monitoring_list'] = opt.monitoring_list

	if opt.scan_mode:
		config['Main']['scan_mode'] = opt.scan_mode


	if opt.extended_list:
		temp_monitoring_list = []
		if opt.monitoring_list:
			logger.error('Using options \'-L\' and \'-E\' in same time not support!')
			sys.exit(1)		
		# alias_string = "vostok-pr11;hp1120;172.21.0.212"
		
		for printer_alias,model,address in [split_strip(x,';') for x in split_strip(opt.extended_list,',')]:
			config['Aliases'][printer_alias] = model + ';' + address			
			temp_monitoring_list.append(printer_alias)
		config['Main']['monitoring_list'] = ",".join(temp_monitoring_list)
		logger.info('List: ' + config['Main']['monitoring_list'])

	if opt.file_name_preffix:
		config['Main']['file_name_preffix'] = opt.file_name_preffix

	if opt.values_for_reading:
		config['Main']['values_for_reading'] = opt.values_for_reading

	if opt.pipe_import:
		config['Main']['pipe_import'] = opt.pipe_import

	if opt.header:		
		config['Main']['header'] = opt.header

	
	if opt.runtime:
		config['Main']['runtime'] = opt.runtime
	else:	
                config['Main']['runtime'] = "False"

	if opt.threads:		
		global THREADS
		THREADS = int(opt.threads)
		config['Main']['threads'] = opt.threads
		
	return

def get_pipe_parser():
	"""Add options from pipe to configparser options"""
	printers = None
	pipe_info_exist = sys.stdin.read()
	if pipe_info_exist:
		# убрать все кавычки из получаемых из pipe данных
		pipe_info_exist = re.sub(r'[\"\'\`]','',pipe_info_exist)
		if ',' in pipe_info_exist:
			printers = split_strip(pipe_info_exist,',')
		else:
			printers = split_strip(pipe_info_exist,'\n')		
	logger.info('export DATA from pipe - ' + pipe_info_exist)
	config['Main']['monitoring_list'] = ",".join(printers)
	return

def get_cfg_parser():
	"""from string to variables"""		
	#global THREADS
	for section, means_dictionary in config.items():
		#logger.info("[",section,"]")
		##pp(dict(means_dictionary.items()))
		options[section] = {}
		for opt, mean in means_dictionary.items():
			#print("* opt %s = %s"%(opt,mean))
			if section == 'Main':
				if opt in ('monitoring_list','values_for_reading'):
					options[section][opt] = split_strip(mean)
				elif opt in ('header','scan_mode','pipe_import','runtime'):
					options[section][opt] = config.getboolean(section,opt)
				elif opt == 'threads':
					global THREADS
					THREADS = int(config.getint(section,opt))
					logger.debug("THREADS " + str(THREADS))	
				else:
					options[section][opt] = mean.strip()

			elif section == 'Aliases':
					options[section][opt.upper()] = split_strip(mean,';')

			else:				
				##pp(options)
				options[section][opt] = mean.strip()
				#sys.exit(2)	
	#pp(options)
	#exit(2)
	return


# SNMP requests Block
def get_snmp_mean(ip=None, snmp_oid=None, proto=1):	
	community='public'
	generator = cmdgen.CommandGenerator().getCmd
	comm_data = cmdgen.CommunityData('server', community, proto) # 1 means version SNMP v2c
	#comm_data = cmdgen.CommunityData('server', community, 0) # 0 means version SNMP v1
	transport = cmdgen.UdpTransportTarget((ip, 161), timeout = 2, retries = 2 )
	value     = cmdgen.MibVariable(snmp_oid)

	res = (errorIndication, errorStatus, errorIndex, varBinds) = generator(comm_data, transport, value)

	if not errorIndication is None  or errorStatus is True:
	       logger.info("Error: %s %s %s %s" % res)
	       return False
	#logger.info("----> %s" % ",".join(["0x%x"%ord(x) for x in str(varBinds[0][1])]) )
	#logger.info("----- %s" % bytes(varBinds[0][1]).decode('utf8','replace'))	
	##pp(res)	
	if type(varBinds[0][1]) == OctetString:
		return bytes(varBinds[0][1]).decode('utf8','replace')
	return str(varBinds[0][1])
		

def request_oids(*args):
	printer_alias, ip, oids = args[0]
	responses = []
	for header, oid in oids:		
		#logger.info(locals())
		snmp_response = get_snmp_mean(ip, oid)	
		if not snmp_response:
				snmp_response = get_snmp_mean(ip, oid, 0)	
		if not snmp_response:
				snmp_response = " --- "							
		if len(snmp_response) >  200:
				snmp_response = '>200 bytes'
		responses.append( (header, snmp_response) )
	return (printer_alias,responses)


def get_data(values_for_reading = ['ALL']):	
	""" Функция выполняет следующее:
					1. собирает все необходимые аргументы для snmp_requests 
					2. опрашивает принтера в многопоточном режиме
					3. на полученных данных формирует массивы "data_headers" и "data" для отчётов
	"""
	snmp_requests 				= []
	snmp_response 				= None		# ответ что вернёт get_snmp_mean() от устройства	

	logger.info("values_for_reading:" + str(options['Main']['values_for_reading']))
	for printer_alias in options['Main']['monitoring_list']:
		global THREADS
		logger.debug('GET DATA from %s' % printer_alias)
		#logger.debug('BIG %s' % str(options['Main']['monitoring_list']))		
		#logger.debug('little %s' % str(options['Aliases']))
		
		data_headers[printer_alias] = []			# Формирование заголовка для устройства printer_alias (e.g.: VOSTOK-PR01)		
		data[printer_alias] = []					# Формирование массива данных для устройства printer_alias (e.g.: VOSTOK-PR01)				
		pr_model, address   = options['Aliases'][printer_alias] 	# Находим тип и адрес устройства
		


		ip   = set_true_ip(address)									# Получаем IP из address
		oids = []	
		header = None	
			
		logger.info("IP4 = " + ip)
		
		# собираем oid для опроса				
		for opt in [x for x in options[pr_model].keys() if 'SNMP_OID' in x.upper()]:			
			try:
				##pp(options[pr_model])								
				value = options[pr_model][opt]				
			except KeyError:
				logger.info('oid - %s N/A in %s'%(opt,str(options[pr_model])))
				value = " !!! "
				continue

			opt = opt.upper()			
			logger.info("Printer:%s,Pr_model:%s, opt: %s, opt in list:%s"%(printer_alias,pr_model, opt,str(opt in options['Main']['values_for_reading'])))
			if opt in options['Main']['values_for_reading'] or values_for_reading == ['ALL']:
				#logger.info('>>>OIDS - %s'%str(oids))		
				header = opt.split('_SNMP_OID')[0]      # remove _SNMP_OID
				# oids = [ ("serialnumber", "1.3.6.1.4.1.1347.43.5.1.1.28.1") ]
				oids.append((header, value))		# добавляем oid-ы для опроса
				data_headers[printer_alias].append(header)		# формируем заголовки таблиц
				data[printer_alias].append('no DATA')			# формируем 


		logger.info('OIDS - %s'%str(oids))		
		snmp_requests.append( (printer_alias, ip, oids) )

	pool = ThreadPool(THREADS)		
	res  = pool.map(request_oids, snmp_requests)	
	
	idx = 0
	logger.info('\n RESPONSES DATA: ')
	for printer_alias, responses in res:
		logger.info('* %s :\n\t\t%s'%(printer_alias,"\t".join(["%s:%s"%(h,v) for h,v in responses])))
		idx = 0
		for header, value in responses:
			# idx - вычисляем какое место в массиве data_headers[printer_alias] имеет данный параметр
			# значит под данным индексом в массиве data[printer_alias] необходимо записать данные 
			idx = data_headers[printer_alias].index(header)			
			data[printer_alias][idx] = value

	#pp(data)	
	return 

def check_printers():
	logger.info('>>>>' + str(options['Main']['monitoring_list']))
	if options['Main']['monitoring_list'] == ['']:
		logger.info('No devices for proccessing')
		sys.exit(0)
	else:
		get_data(options['Main']['values_for_reading'])
	return

# Visualization Block
def make_table(empty=False):		
	max_rows_len = 0
	max_headers_len = 0
	raw_table = []
	header = []
	header2 = []
	cnt = 0
	row = []
	printer_data = None
	printer_alias_for_header = tuple(data_headers.values())[0]
	# Формируем заголовок таблицы. Узнаём у какого принтера больше параметров было считано,
	# берём его параметры за заголовок
	for printer_alias, headers in data_headers.items():
		if len(headers) > max_headers_len:
				max_headers_len = len(headers)
				printer_alias_for_header = printer_alias
		# В заголовок берём название oid-ок от принтера с самым большим количеством oid-ок
		if not max_headers_len:
			logger.info('no DATA')
			exit(1)
		logger.info(str(data_headers) + '=' + str(data_headers))
		logger.info(printer_alias_for_header)
		
		if options['Main']['values_for_reading'] == ['ALL']:
			header = data_headers[printer_alias_for_header] 
		else:
			header = [x.split('_SNMP_OID')[0] for x in options['Main']['values_for_reading'] ]
		
		if options['Main']['header']:
			header = ['n/n','Printer'] + header


		raw_table = []
					
		raw_table.append(header)
		cnt = 0
		row = []	
		printer_data = None		

	# Формируем табличные данные в соответствии с той очередностьбю что задана в ['Main']['monitoring_list']
	for printer_alias in options['Main']['monitoring_list']:
		logger.info("***** printer_alias" + printer_alias)
		#for printer_alias in data.keys():
		logger.info("Printer " + printer_alias)
		row = []
		# создаём словарь для printer_alias(vostok-pr11) {oid_name: mean }{'model':'FS-3920DN',...}
		printer_data = dict(zip(data_headers[printer_alias],data[printer_alias]))
		cnt += 1
		if options['Main']['header']:
			printer_data['n/n'] = str(cnt)
			printer_data['Printer'] = printer_alias


		logger.info("HEADER= " + str(header))
		logger.info("printer_data = " + str(printer_data))
		for oid_name in header:
			if oid_name in printer_data.keys():
				row.append(printer_data[oid_name])
			else:
				row.append(" N/A ")
		raw_table.append(row)
	# Если нет заголовка, то убираем первую строчку
	if not options['Main']['header']:
		raw_table.pop(0)	
	return raw_table



def get_results():
	res = None
	raw_table = make_table()	
	if options['Main']['mode'] == 'plaintext':
		import csv, io
		output = io.StringIO()
		with output:
			rec = csv.writer(output,delimiter=' ')				
			rec.writerows(raw_table)
			logger.info(str(raw_table))
	elif options['Main']['mode'] == 'plaintable':		
		import output_func		
		#logger.info(str(raw_table))
		res = output_func.print_table(raw_table)
		logger.info('\n' + res)
		print(res)
	elif options['Main']['mode'] == 'csv':
		import csv
		logger.info("Save data to \'%s\'' ]file"%options['Main']['file_name_preffix'])
		f = open(options['Main']['file_name_preffix'] + '.csv','w', newline='')	
		with f as csvfile:
			rec = csv.writer(csvfile,dialect='excel',delimiter=';')				
			rec.writerows(raw_table)
		logger.info(open(options['Main']['file_name_preffix'],'r').read())
	elif options['Main']['mode'] == 'html':
		import output_func		
		data = output_func.html_table(raw_table,"Printer statistic [%s]"%datetime.now().strftime('%d.%m.%Y %H:%M:%S'))
		#pp(data)
		data = data.encode('cp1251','replace').decode('cp1251','replace')
		logger.info("Save data to \'%s\'' ]file"%options['Main']['file_name_preffix'])		
		with open(options['Main']['file_name_preffix'] + '.html','w') as save_file:
			save_file.write(data)				
	return raw_table
		


# Main
def main(**args):	
	print(args)
	runtime	= time()
	if args == {}:
		logger.info('==== [ OPT PARSER ] ====')	
		get_opt_parser()	
		#logger.info(">*>",config['Main']['scan_mode'])
	else:
		sys.argv = ['','-M','plaintext']
		get_opt_parser(called_from_module = True)	
		for section, means_dictionary in config.items():					
			for opt, mean in means_dictionary.items():
				if args.get(section):
					if args[section].get(opt):
						config[section][opt] = str(args[section][opt])		

	if to_boolean(config['Main']['pipe_import']) == True:
		logger.info('\n\n\n\n ==== [ PIPE IMPORT ] ====')	
		get_pipe_parser()
	if to_boolean(config['Main']['scan_mode']) == True:
		logger.info('\n\n\n\n ==== [ ADD EXTRA OPTIONS ] ====')	
		add_extra_options()		

	logger.info('\n\n\n\n ==== [ CFG PARSER ] ====')	
	get_cfg_parser()
	logger.info('\n\n\n\n ==== [ CHECK PRINTERS ] ====')	
	check_printers()
	logger.info('\n\n\n\n ==== [ GET RESULT ] ====')	
	res = get_results()
	logger.info('\nRUNTIME : %.2f sec.'% (time() - runtime))	
	#if options['Main']['runtime']:
	#	print("\n\nRUNTIME : %.2f sec."% (time() - runtime))
	if args == {}: 
		pass
		#sys.exit(0)		
	return res 

if __name__ == '__main__':	
	main()

