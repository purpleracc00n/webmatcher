#!/usr/bin/python3

import argparse
import subprocess
import ipaddress
import sys
import time
import dns.resolver
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description='Tool to better manage external attack surface. It attempts to match public hostname dns records to IPs within ranges provided to uncover web services.')
parser.add_argument("scope_file",type=str,help="file containing the in-scope IPs, IP ranges and/or CIDRs (one per line).")
parser.add_argument("domain",type=str,help="target domain")
parser.add_argument("-o","--output",type=str,help="file to save valid subdomains to")
parser.add_argument("-w","--wordlist",type=str,help="custom subdomain file to use for DNS grinding.",default="default")
parser.add_argument("-s","--subdomainsfile",type=str,help="list of known subdomains to add for these checks on top of discovered ones.")
# add option to add your own valid subdomain file
# add reverse dns lookup?
args = parser.parse_args()

IPs_list = []

def load_scope(filename):
	with open(filename, "r") as scope:		
		for line in scope:
			# process CIDR
			if "/" in line:
				for ip in ipaddress.IPv4Network(line.rstrip()):
					IPs_list.append(int(ip))
			# process range
			elif "-" in line:
				start_ip = line.split("-")[0]
				end_ip = line.split("-")[1].rstrip()
				start_ip_binary = int(ipaddress.IPv4Address(start_ip))
				end_ip_binary = int(ipaddress.IPv4Address(end_ip))
				for i in range(start_ip_binary,end_ip_binary+1):
					IPs_list.append(i)
			# process IP
			else:
				IPs_list.append(int(ipaddress.IPv4Address(line.rstrip())))

def amass_scan(domain,wordlist):
	if(wordlist!="default"):
		cmd_output = ""
		process = subprocess.Popen(['amass', 'enum', '-d', domain, '-brute', '-w', wordlist], stdout=subprocess.PIPE, text=True)
		while True:
			output = process.stdout.readline()
			if output == '' and process.poll() is not None:
				break
			if output:
				print(output.strip())
			cmd_output += output
		return cmd_output
	else:
		cmd_output = ""
		process = subprocess.Popen(['amass', 'enum', '-d', domain, '-brute'], stdout=subprocess.PIPE, text=True)
		while True:
			output = process.stdout.readline()
			if output == '' and process.poll() is not None:
				break
			if output:
				print(output.strip())
				cmd_output += output
		return cmd_output
		
		
def theharvester_scan(domain):
	cmd_output = ""
	process = subprocess.Popen(['theHarvester', '-v', '-d', domain, '-l', '1000', '-b', 'all'], stdout=subprocess.PIPE, text=True)
	hosts_found_flag = False
	while True:
		output = process.stdout.readline()
		if "[*] Hosts found:" in output:
			hosts_found_flag = True
		if output == '' and process.poll() is not None:
			break
		if output and hosts_found_flag:
			print(output.strip())
			cmd_output += output
	return cmd_output		

def match_subdomains(subdomain_list):
	inscope = []
	for subdomain in subdomain_list:
		answer = ""
		try:
			answer = dns.resolver.resolve(subdomain, 'A')
		except:
			# subdomain did not resolve
			continue
		for ipval in answer:
    			if(int(ipaddress.IPv4Address(ipval.to_text())) in IPs_list):
    				print(bcolors.OKGREEN + "[+] Found in-scope subdomain: " + subdomain + " resolving to " + ipval.to_text() + bcolors.ENDC)
    				inscope.append(subdomain)
	return inscope

def extract_sombdomain_file(file):
	subdomain_list = []
	with open(file, "r") as subdomains:		
		for subdomain in subdomains:
			subdomain_list.append(subdomain.rstrip())
	return subdomain_list

def main():
	print(bcolors.OKCYAN + "[*] Initiating..." + bcolors.ENDC)
	try:
		load_scope(args.scope_file)
		print(bcolors.OKGREEN + "[+] Scope loaded..." + bcolors.ENDC)
	except Exception as e:
		print(bcolors.FAIL + f'[-] Could not load scope. Error in values provided within {args.scope_file}: {str(e)}' + bcolors.ENDC)
		sys.exit(0)
	print(bcolors.OKCYAN + "[*] Discovering subdomains... this might take a while..." + bcolors.ENDC)
	print(bcolors.OKCYAN + "[*] Running amass..." + bcolors.ENDC)
	amass_output = amass_scan(args.domain,args.wordlist)
	print(bcolors.OKCYAN + "[*] Running theharvester..." + bcolors.ENDC)
	theharvester_output = theharvester_scan(args.domain)
	
	regexed_domain = args.domain.replace(".","\.")
	
	subdomains_amass = re.findall(r'([a-z0-9\-]+[.]*{})'.format(regexed_domain), amass_output)
	subdomains_harvester = re.findall(r'([a-z0-9\-]+[.]*{})'.format(regexed_domain), theharvester_output)
	subdomains = set(subdomains_amass + subdomains_harvester)
	
	if(args.subdomainsfile):
		subdomains.extend(extract_sombdomain_file(args.subdomainsfile))
		subdomains = set(subdomains)
	
	
	if(len(subdomains)>0):
		print(bcolors.OKGREEN + "[+] Found the following subdomains: " + bcolors.ENDC)
		for subdomain in subdomains:
			print(subdomain)
	else:
		print(bcolors.FAIL + "[-] No subdomains were found, exiting..." + bcolors.ENDC)
		
	inscope_subdomains = match_subdomains(subdomains)
	for subdomain in inscope_subdomains:
		print(subdomain)	

if __name__ == "__main__":
	main()
