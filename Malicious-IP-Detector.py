import sys
import re
import socket
import fcntl
import struct
import requests
import json
import pprint
import virustotal2
import urllib2
import csv
from ipwhois import IPWhois
from urllib2 import urlopen


def storeip(): #Extract only ip addresses from the snort alert logs and store the ip addresses in a new file

	try:

		iplist = []
		logs = ''
		if sys.argv[1:]:
	       		print "File: %s" % (sys.argv[1])
			logs = sys.argv[1]
		else:
    			print "Format: \n\n'python Malicious_IP_Detect.py filename/path'\n"


	        file1 = open(logs, "r")
		

		for ip in file1.readlines():
	    		ip = ip.rstrip()
	   		foundip = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',ip)
		    	if foundip:
		      		iplist.extend(foundip) 
		
		for ip in iplist:
			try:
				file2 = open("test.txt", "a")
			except:	
				print "Error: File not found."
				sys.exit()
 			line = "".join(ip)
	        	if line is not '':
	           		print "IP: %s" % (line)
	           		file2.write(line)
	           		file2.write("\n")
		   		file2.close()
    
		file1.close()

    
	except IOError, (errno, strerror):
	        print "I/O Error(%s) : %s" % (errno, strerror)
		sys.exit()

	iterateip()



def iterateip():#Parsing through the file containing the extracted IP addresses

	storedips = "test.txt"
	file2 = ''
	try:
	        file2 = open(storedips, "r")
	except:
		print "Error: File not found."
		sys.exit()
	ipaddress = get_ip_address('eth0') #Get IP address of current system
	file2 = open(storedips, "r")
	for ips in file2.readlines():
    		ips = ips.rstrip()
		url = ""
		try:

			ipa = socket.gethostbyaddr(ips)
			url = ipa[0]
		
		except: 
			print ""
		
		if ips == ipaddress:
			print ""
		else: 
			
			x = googleapi(url)
					
			if x == False:	#Checking if IP address is malicious according to Google SafeBrowsing API	
				ipgeolocate(ips)  #If not safe, get information of the malicious IP address
			else:
				print "Google: " + ips + "=> IP not malicious\n" 
	virustotal()
	
				
	

def get_ip_address(ifname):

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915, struct.pack('256s', ifname[:15]))[20:24])
	sock.close()


def virustotal():
	

	
	mdl_content = urllib2.urlopen("http://www.malwaredomainlist.com/mdlcsv.php")
	mdl_csv = csv.reader(mdl_content)
	file3 = open("malwaredomains.txt", "w")
	file3.seek(0)
	file3.truncate()
	file3.close()
	for line in mdl_csv:
		try:
		
			ip=line[2].split("/")[0]
		except:
			virus()		
			
		file3 = open("malwaredomains.txt", "a")
 		line = "".join(ip)
		
       		if line is not '':
       	   	
       	   		file3.write(line)
			
       	   		file3.write("\n")
	   			
	virus()
		
def virus():	
	vt = virustotal2.VirusTotal2("#INSERT_API_KEY_HERE#")
		
	
	file4 = open("test.txt", "r")
	for ip in file4.readlines():
		ip = ip.rstrip()
		
		file3 = open("malwaredomains.txt", "r")
		for ips in file3.readlines():
			ips = ips.rstrip()
				
		if ip == ips:
					
			ip_report = vt.retrieve(ip)   #get the VT IP report for this IP
			total_pos = sum([u["positives"] for u in ip_report.detected_urls])
			total_scan = sum([u["total"] for u in ip_report.detected_urls])
			count = len(ip_report.detected_urls)
			print str(count)+" URLs hosted on "+ip+" are called malicious by (on average) " + \
	      		str(int(total_pos/count)) + " / " + str(int(total_scan/count)) + " scanners"		
			ipgeolocate(ips)


def googleapi(ip):
	key = '#INSERT_API_KEY_HERE#'
	URL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=api&apikey={key}&appver=1.0&pver=3.0&url={url}"

	def safeip(key, url):
    		response = requests.get(URL.format(key=key, url=url))
   		return response.text != 'malware'
	
	TrueorFalse = safeip(key, ip)
	return TrueorFalse


def ipgeolocate(ip):

	print ip
	def extremeiplookup():
			
			url = 'https://extreme-ip-lookup.com/json/' + ip
	    		result = requests.head(url)	
	
			if result.status_code != 200:
				print "Unable to fetch data. Switching to whois.com:"
				whois()
				
			
			output(url)
			return url		
			
	
	def whois():
	
			obj = IPWhois(ip)
			results = obj.lookup_rws()
			pprint.pprint(results)
			
	
	def output(url1):
	
			response = urlopen(url1)
			datafound = json.load(response)
	
	
			city = datafound['city']
			region = datafound['region']
	
			if 'query' in datafound:
				IP = datafound['query']
			elif 'ip' in datafound: 
				IP = datafound['ip']
			if 'organisation' in datafound: 
				organisation = datafound['organisation']
			elif 'org' in datafound:
				organisation = datafound['org']
			if 'country_name' in datafound: 
				country = datafound['country_name']
			elif 'country' in datafound:
				country = datafound['country']
			if 'asn' in datafound:
				asn = datafound['asn']
				print '**********************************************************************************************'
				output = '\nInformation Found: \nIP: {0} \nRegion: {1} \nCountry: {2} \nCity: {3} \nOrg: {4} \nASN: {5}'.format(IP,region,country,city,organisation,asn)
			else:
				print '**********************************************************************************************'
				output = '\nInformation Found: \nIP: {0} \nRegion: {1} \nCountry: {2} \nCity: {3} \nOrg: {4}'.format(IP,region,country,city,organisation)
				
	
			file3 = open("Output.txt", "a")
	 		result = "".join(output)
	        	if result is not '':
	           		print "GeoInfo: %s" % (result)
	           		file3.write(result)
	           		file3.write("\n")
		   		file3.close()





    	extremeiplookup()





if __name__ == "__main__":
	storeip()
