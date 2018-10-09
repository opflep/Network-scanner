import socket

def get_sub(filepath):
	sub_dict = []
	try:  
	    fp = open(filepath)    
	    line = fp.readline()
	    while line:
	    	sub_dict.append(line.strip())
	    	line = fp.readline() 

	finally:  
	    fp.close()
	return sub_dict

def scan(domain, sub_dict):
	print "Scanning..."
	print "========================================================="
	sub_list = []
	for i in sub_dict:
		sub_domain = i + "." + domain
		try:
			ip = socket.gethostbyname(sub_domain)
			sub_list.append(sub_domain)
			print ip + " : " + sub_domain
		except:
			# print "Fail " + i
			pass
	print "========================================================="
	print "Scan Done"	

def export_file(sub_list,fileName):
	file = open(fileName,"w")
	for sub in sub_list:
		file.write(sub)
	file.close()
	print "Your result is exported to " + fileName

def main():
	sub_dict = get_sub("sub.txt")
	domain = raw_input("Enter domain to scan: ")
	sub_list = scan(domain,sub_dict)
	output = domain + "_result.txt"
	export_file(sub_list,output)










if __name__ == '__main__':  
   main()