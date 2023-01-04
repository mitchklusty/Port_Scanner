# port scanner

import socket, sys, time
from threading import Thread

if len(sys.argv) > 1: 
	target = sys.argv[1]
else:
	print("Input target IP as command line arg")
	exit(0)

common_protocols = {
	7: {'Name': 'Echo', 'Protocol': 'TCP, UDP', 'Description': 'Echo service'},
	20: {'Name': 'FTP-data', 'Protocol': 'TCP, SCTP', 'Description': 'File Transfer Protocol data transfer'},
	21: {'Name': 'FTP', 'Protocol': 'TCP, UDP, SCTP', 'Description': 'File Transfer Protocol (FTP) control connection'},
	22: {'Name': 'SSH-SCP', 'Protocol': 'TCP, UDP, SCTP ', 'Description': 'Secure Shell, secure logins, file transfers (scp, sftp), and port forwarding'},
	23: {'Name': 'Telnet', 'Protocol': 'TCP', 'Description': 'Telnet protocol—unencrypted text communications'},
	25: {'Name': 'SMTP', 'Protocol': 'TCP', 'Description': 'Simple Mail Transfer Protocol, used for email routing between mail servers'},
	53: {'Name': 'DNS', 'Protocol': 'TCP, UDP', 'Description': 'Domain Name System name resolver'},
	69: {'Name': 'TFTP', 'Protocol': 'UDP', 'Description': 'Trivial File Transfer Protocol'},
	80: {'Name': 'HTTP', 'Protocol': 'TCP, UDP, SCTP', 'Description': 'HTTP port'},
	88: {'Name': 'Kerberos', 'Protocol': 'TCP, UDP', 'Description': 'Network authentication system'},
	102: {'Name': 'Iso-tsap', 'Protocol': 'TCP', 'Description': 'ISO Transport Service Access Point (TSAP) Class 0 protocol'},
	110: {'Name': 'POP3', 'Protocol': 'TCP', 'Description': 'Post Office Protocol, version 3 (POP3)'},
	135: {'Name': 'Microsoft EPMAP', 'Protocol': 'TCP, UDP', 'Description': 'Microsoft EPMAP (End Point Mapper), also known as DCE/RPC Locator service, used to remotely manage services including DHCP server, DNS server, and WINS. Also used by DCOM'},
	137: {'Name': 'NetBIOS-ns', 'Protocol': 'TCP, UDP', 'Description': 'NetBIOS Name Service, used for name registration and resolution'},
	139: {'Name': 'NetBIOS-ssn', 'Protocol': 'TCP, UDP', 'Description': 'NetBIOS Session Service'},
	143: {'Name': 'IMAP4', 'Protocol': 'TCP, UDP', 'Description': 'Internet Message Access Protocol (IMAP), management of electronic mail messages on a server'},
	381: {'Name': 'HP Openview', 'Protocol': 'TCP, UDP', 'Description': 'HP data alarm manager'},
	383: {'Name': 'HP Openview', 'Protocol': 'TCP, UDP', 'Description': 'HP data alarm manager'},
	443: {'Name': 'HTTP over SSL', 'Protocol': 'TCP, UDP, SCTP', 'Description': 'Hypertext Transfer Protocol Secure (HTTPS) uses TCP in versions 1.x and 2. HTTP/3 uses QUIC, a transport protocol on top of UDP.'},
	464: {'Name': 'Kerberos', 'Protocol': 'TCP, UDP', 'Description': 'Kerberos Change/Set password'},
	465: {'Name': 'SMTP over TLS/SSL, SSM', 'Protocol': 'TCP', 'Description': 'Authenticated SMTP over TLS/SSL (SMTPS), URL Rendezvous Directory for SSM (Cisco protocol)'},
	587: {'Name': 'SMTP', 'Protocol': 'TCP', 'Description': 'Email message submission'},
	593: {'Name': 'Microsoft DCOM', 'Protocol': 'TCP, UDP', 'Description': 'HTTP RPC Ep Map, Remote procedure call over Hypertext Transfer Protocol, often used by Distributed Component Object Model services and Microsoft Exchange Server'},
	636: {'Name': 'LDAP over TLS/SSL', 'Protocol': 'TCP, UDP', 'Description': 'Lightweight Directory Access Protocol over TLS/SSL'},
	691: {'Name': 'MS Exchange', 'Protocol': 'TCP', 'Description': 'MS Exchange Routing'},
	902: {'Name': 'VMware Server', 'Protocol': 'unofficial', 'Description': 'VMware ESXi'},
	989: {'Name': 'FTP over SSL', 'Protocol': 'TCP, UDP', 'Description': 'FTPS Protocol (data), FTP over TLS/SSL'},
	990: {'Name': 'FTP over SSL', 'Protocol': 'TCP, UDP', 'Description': 'FTPS Protocol (control), FTP over TLS/SSL'},
	993: {'Name': 'IMAP4 over SSL', 'Protocol': 'TCP', 'Description': 'Internet Message Access Protocol over TLS/SSL (IMAPS)'},
	995: {'Name': 'POP3 over SSL', 'Protocol': 'TCP, UDP', 'Description': 'Post Office Protocol 3 over TLS/SSL'},
	1025: {'Name': 'Microsoft RPC', 'Protocol': 'TCP', 'Description': 'Microsoft operating systems tend to allocate one or more unsuspected, publicly exposed services (probably DCOM, but who knows) among the first handful of ports immediately above the end of the service port range (1024+).'},
	1194: {'Name': 'OpenVPN', 'Protocol': 'TCP, UDP', 'Description': 'OpenVPN'},
	1337: {'Name': 'WASTE', 'Protocol': 'unofficial', 'Description': 'WASTE Encrypted File Sharing Program'},
	1589: {'Name': 'Cisco VQP', 'Protocol': 'TCP, UDP', 'Description': 'Cisco VLAN Query Protocol (VQP)'},
	1725: {'Name': 'Steam', 'Protocol': 'UDP', 'Description': 'Valve Steam Client uses port 1725'},
	2082: {'Name': 'cPanel', 'Protocol': 'unofficial', 'Description': 'cPanel default'},
	2083: {'Name': 'radsec, cPanel', 'Protocol': 'TCP, UDP', 'Description': 'Secure RADIUS Service (radsec), cPanel default SSL'},
	2483: {'Name': 'Oracle DB', 'Protocol': 'TCP, UDP', 'Description': 'Oracle database listening for insecure client connections to the listener, replaces port 1521'},
	2484: {'Name': 'Oracle DB', 'Protocol': 'TCP, UDP', 'Description': 'Oracle database listening for SSL client connections to the listener'},
	2967: {'Name': 'Symantec AV', 'Protocol': 'TCP, UDP', 'Description': 'Symantec System Center agent (SSC-AGENT)'},
	3074: {'Name': 'XBOX Live', 'Protocol': 'TCP, UDP', 'Description': 'Xbox LIVE and Games for Windows – Live'},
	3306: {'Name': 'MySQL', 'Protocol': 'TCP', 'Description': 'MySQL database system'},
	3724: {'Name': 'World of Warcraft', 'Protocol': 'TCP, UDP', 'Description': 'Some Blizzard games, Unofficial Club Penguin Disney online game for kids'},
	4664: {'Name': 'Google Desktop', 'Protocol': 'unofficial', 'Description': 'Google Desktop Search'},
	5432: {'Name': 'PostgreSQL', 'Protocol': 'TCP', 'Description': 'PostgreSQL database system'},
	5900: {'Name': 'RFB/VNC Server', 'Protocol': 'TCP, UDP', 'Description': 'virtual Network Computing (VNC) Remote Frame Buffer RFB protocol'},
	6665: {'Name': 'IRC', 'Protocol': 'TCP', 'Description': 'Internet Relay Chat'},
	6669: {'Name': 'IRC', 'Protocol': 'TCP', 'Description': 'Internet Relay Chat'},
	6881: {'Name': 'BitTorrent', 'Protocol': 'unofficial', 'Description': 'BitTorrent is part of the full range of ports used most often'},
	6999: {'Name': 'BitTorrent', 'Protocol': 'unofficial', 'Description': 'BitTorrent is part of the full range of ports used most often'},
	6970: {'Name': 'Quicktime', 'Protocol': 'unofficial', 'Description': 'QuickTime Streaming Server'},
	8086: {'Name': 'Kaspersky AV', 'Protocol': 'TCP', 'Description': 'Kaspersky AV Control Center'},
	8087: {'Name': 'Kaspersky AV', 'Protocol': 'UDP', 'Description': 'Kaspersky AV Control Center'},
	8222: {'Name': 'VMware Server', 'Protocol': 'TCP, UDP', 'Description': 'VMware Server Management User Interface (insecure Web interface).'},
	9100: {'Name': 'PDL', 'Protocol': 'TCP', 'Description': 'PDL Data Stream, used for printing to certain network printers[1'},
	10000: {'Name': 'BackupExec', 'Protocol': 'unofficial', 'Description': 'Webmin, Web-based Unix/Linux system administration tool (default port)'},
	12345: {'Name': 'NetBus', 'Protocol': 'unofficial', 'Description': 'NetBus remote administration tool (often Trojan horse).'},
	27374: {'Name': 'Sub7', 'Protocol': 'unofficial', 'Description': 'Sub7 default'},
	18006: {'Name': 'Back Orifice', 'Protocol': 'unofficial', 'Description': 'Back Orifice 2000 remote administration tools'},
}

class ThreadWithReturnValue(Thread):
	def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
		Thread.__init__(self, group, target, name, args, kwargs)
		self._return = None
	def run(self):
		if self._target is not None:
			self._return = self._target(*self._args, **self._kwargs)
	def join(self, *args):
		Thread.join(self, *args)
		return self._return

def scanPorts(target, low, high):
	results = []
	open_ports = []
	try:
		for port in range(low, high):
			# print(f"Scanning port {port}", end='\r')
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(0.5)
			result = s.connect_ex((target, port))
			if result not in results:
				results.append(result)
			if result == 0:
				open_ports.append(port)
				# open_ports[target].append(port)
				# print(f"[{target}]: Port {port} is open")
			s.close()
	except KeyboardInterrupt:
		print("Exiting")
		exit(0)
	except socket.error as e:
		print(e)
		print("Target did not respond")
	except:
		pass
	return open_ports

def scanIP(target):
	open_ports = []
	num_ports = 65535
	interval = int(num_ports/771)
	threads = []
	for i in range(0, num_ports, interval):
		threads.append(ThreadWithReturnValue(target=scanPorts, args=(target, i, i+interval,)))
		threads[int(i/interval)].start()
	for t in threads:
		ports = t.join()
		for p in ports:
			open_ports.append(p)
	return open_ports

def largest_length(key, ports):
	max_len = 0
	for p in ports:
		if len(common_protocols[p][key]) > max_len:
			max_len = len(common_protocols[p][key])
	return max_len

def check_common_ports(ports):
	found = []
	not_found = []
	for port in ports:
		if port in common_protocols.keys():
			found.append(port)
		else:
			not_found.append(port)
	name_length, protocol_length = largest_length("Name", found)+3, largest_length("Protocol", found)+3
	print(f"Port\t{'Name'.ljust(name_length)}{'Protocol'.ljust(protocol_length)}Description")
	for f in found:
		print(f"{f}:\t{common_protocols[f]['Name'].ljust(name_length)}{common_protocols[f]['Protocol'].ljust(protocol_length)}{common_protocols[f]['Description']}")
	if len(not_found) > 0:
		uncommon = ""
		for p in not_found:
			uncommon += str(p) + " "
		print(f"Unknown Protocols: {p}")


p = scanIP(target)
print(f"Open Ports: {p}")
check_common_ports(p)
