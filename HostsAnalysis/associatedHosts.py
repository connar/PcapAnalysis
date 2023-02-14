import pyshark
import requests
import sys
from tabulate import tabulate
from termcolor import colored
import nest_asyncio
nest_asyncio.apply()

def virusTotalRequest(protocol,apiKey,associatedHosts):
	results = []
	for host in associatedHosts.keys():
		host_results = []
		url = f"https://www.virustotal.com/api/v3/domains/{str(host)}"
		header = {'x-apikey': f'{apiKey}'}
		response = requests.get(url, headers=header).json()

		votes = response["data"]["attributes"]["last_analysis_stats"]
		
		if votes["malicious"] > 0:
			host_colored = colored(host, 'red')
		elif votes["suspicious"] > 0:
			host_colored = colored(host, 'yellow')
		else:
			host_colored = colored(host, 'green')
		results.append([protocol, host_colored, votes["malicious"], votes["suspicious"], votes["harmless"], votes["undetected"], associatedHosts[host]])
	
	print(tabulate(results, headers=["Protocol", "Host", "Malicious", "Suspicious", "Harmless", "Undetected", "Time of interaction"]))


def trafficAnalysisForHTTP(ipSrc,apiKey):
	pcapFilter = f"http and ip.src == {ipSrc}"
	pktsHttp = pyshark.FileCapture(str(sys.argv[3]),display_filter=pcapFilter)

	associatedHosts = {}
	for p in pktsHttp:
		if p.http.host not in associatedHosts:
			associatedHosts[p.http.host] = p.frame_info.time

	virusTotalRequest("http",apiKey,associatedHosts)


def trafficAnalysisForHTTPS(ipSrc,apiKey):
	pcapFilter = f"tls and ip.src == {ipSrc}"
	pktsTls = pyshark.FileCapture(str(sys.argv[3]),display_filter=pcapFilter)

	associatedHosts = {}
	for p in pktsTls:
		if "tls.handshake.extensions_server_name" in p.tls._all_fields.keys():
			if p.tls._all_fields["tls.handshake.extensions_server_name"] not in associatedHosts:
				associatedHosts[p.tls._all_fields["tls.handshake.extensions_server_name"]] = p.frame_info.time

	virusTotalRequest("tls",apiKey,associatedHosts)

try:
	if len(sys.argv) != 4:
		print("Usage : python3 associatedHosts.py [ipSrc] [apiKey] [pcap]")
		quit()
	print("\U0001F534 : Malicious \n\U0001F7E0 : Suspicious \n\U0001F7E2 : Harmless")

	ipSrc = sys.argv[1]
	apiKey = sys.argv[2]

	print("\nHTTP traffic analysis found the following: \n")
	trafficAnalysisForHTTP(ipSrc,apiKey)


	print("\n\nHTTPS traffic analysis found the following: \n")
	trafficAnalysisForHTTPS(ipSrc,apiKey)
except Exception as e: 
	print(e)
