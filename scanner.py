import socket 
import functools
import ipaddress
from scapy.all import *
import netaddr

def is_Alive(host):
	packet =IP(dst=str(host))/ICMP()
	resp = sr1(packet,timeout=2,verbose=0)
	if (str(type(resp)) == "<type 'NoneType'>"):
		print (str(host) + " is down or not responding.")
		return 0
	elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	        print (str(host) + " is blocking ICMP.")
	        return 0
	else:
		print (str(host) + " is responding.")
		return 1

def get_open_TCP_port(ip):
	print 'Scanning IP: '+ ip 
	print '--------------------------------------- '
	# list = []
	# 
	if (is_Alive(ip)!=1):
		return
	try:
		for port in range (0,1024):
			socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
			socket.setdefaulttimeout(1) 
			result = socket_obj.connect_ex((ip,port))
			if result == 0 :
				 print "Port {}: 	 Open".format(port)
				# list.append(port)
			socket_obj.close()
	except:
		pass
	# return list

def get_list_host(range):
	ip_list = list(ipaddress.ip_network(unicode(range)).hosts())
	rs = []
	for ip in ip_list:
		rs.append(str(ip))
	return rs


remoteIP = raw_input("Enter IP or IP range: ")
ip_list = get_list_host (remoteIP)
if (len(ip_list)== 0):
	get_open_TCP_port(remoteIP)
else:
	for ip in ip_list:
		get_open_TCP_port(ip)



