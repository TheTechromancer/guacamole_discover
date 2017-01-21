#!/usr/bin/python3

import subprocess as sp
from ipaddress import ip_network
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from tempfile import NamedTemporaryFile
from xml.dom.minidom import parseString

### DEFAULTS ###

services = {
	#port		#protocol
	'22':		'ssh',
	'23':		'telnet',
	'3389':		'rdp',
	'5900':		'vnc',
}

# used for finding local subnet
interface_keywords = ['enp', 'wlp', 'eth', 'wlan']

def get_subnet():
	'''
	returns ip_network object for first "eth" interface
	'''

	# ugly, I know
	# runs command, splits by newline, enumerates, converts to list
	output = list(enumerate(sp.run(['ip', 'address'], stdout=sp.PIPE).stdout.decode().split('\n')))

	for line in output:

		try:

			# finds line starting with <interface_keywords> and gets the full interface name
			l = [ line[1].split()[1].startswith(k) for k in interface_keywords ]

			if any( l ):
				
				# tries to get the interface's IP
				ip_info = output[line[0]+2][1].split()
				if ip_info[0] == 'inet':
					return str(ip_network(ip_info[1], strict=False))

		except IndexError:
			# keep moving if no IP is found
			continue

	# returns 'None' if no IP is found
	return None


### CLASSES ###


class Host():
	
	def __init__(self, ip=None, mac=None, hostname=None, ports=None):
		self.ip			= ip
		self.mac		= mac
		self.hostname	= hostname
		self.ports		= ports


class Nmap():

	def __init__(self, targets, ports=services.keys()):
		'''
		translates function parameters into shell arguments
		'''

		self._check_progs(['nmap'])
		self.args_list=[]

		# accepts either string or list
		if type(targets) == str: targets = [targets]

		if ports:
			if type(ports) == str:
				self.args_list.append("-p {}".format(ports))
			else:
				self.args_list.append("-p {}".format(','.join(ports)))


		self.targets	= ' '.join(targets)
		self.data		= []


	def start(self):

		# temp file used for xml output
		self.tmpfile = NamedTemporaryFile(delete=False)

		# build nmap command
		cmd_list = ["nmap", "--open", "-R", "-oX", self.tmpfile.name]
		cmd_list.extend(self.args_list)
		cmd_list.append(self.targets)

		# run nmap command
		print('>> ', ' '.join(cmd_list)) # debugging
		self.process = sp.Popen(cmd_list, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
		
		return self.results()


	def results(self):
		'''
		generates:	self.data - dictionary in form { 'ip_address': (open_tcp_ports) }
		'''

		if self.data:
			return self.data

		# wait for process to finish
		try:
			self.process.wait()
			# print(type(self.process.returncode))
		except sp.TimeoutExpired:
			self.process.terminate()

		if self.process.returncode == 0:

			# parse xml
			try:

				tree = ET.parse(self.tmpfile.name)
				hosts = tree.findall('host')

				for host in hosts:

					h = Host()
					ports = []

					h.ip = host.find('address').attrib['addr']
					try:
						h.hostname = host.find('hostnames').find('hostname').attrib['name']
					except AttributeError:
						pass

					# put ports in set like { '80', '443', ... }
					for p in host.find('ports').findall('port'):

						# if port is open
						if p.find('state').attrib['state'] == 'open':
							# add port to list
							ports.append(p.attrib['portid'])

					if ports:
						h.ports = ports
						self.data.append( h )

			finally:
				self.tmpfile.close()

		return self.data


	def _check_progs(self, prog_list):
		'''
		takes:		list of executable files in string form
		purpose:	raise SystemError if binaries cannot be found
		'''
		install_progs = []

		for prog in prog_list:
			try:
				sp.run(['hash', prog], shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL, check=True)
				# sp.run("hash {} 2>/dev/null".format(prog), shell=True, check=True)
			except:
				install_progs.append(prog)

		if install_progs: raise SystemError('Programs required:\n{}\n'.format(' '.join(install_progs)))



def gen_config(scan_results, username, password):

	user_mapping = ET.Element('user-mapping')

	authorize = ET.SubElement(user_mapping, 'authorize')
	authorize.set('username', username)
	authorize.set('password', password)

	for host in scan_results:
		for port in host.ports:

			if host.hostname is not None:
				name = "{}:{} ({})".format(host.ip, port, host.hostname.split('.')[0])
			else:
				name = "{}:{}".format(host.ip, port)

			#try:

			connection = ET.SubElement(authorize, 'connection')

			# connection name
			connection.set('name', name)

			protocol = ET.SubElement(connection, 'protocol')
			protocol.text = services[port]

			# hostname
			param1 = ET.SubElement(connection, 'param')
			param1.set('name', 'hostname')
			param1.text = host.ip

			# port
			param2 = ET.SubElement(connection, 'param')
			param2.set('name', 'port')
			param2.text = port

			#except:
			#	print("Error in gen_config")

	return user_mapping



if __name__ == '__main__':

	### START ARG SETUP ###

	parser = ArgumentParser(description='Scan for hosts, generate Guacamole XML config file')
	parser.add_argument('-t', '--target',	default=get_subnet(),			help='IP range or host.  Defaults to local subnet',)
	parser.add_argument('-o', '--output',	default='./user-mapping.xml',	help='Output to xml file.  Default is "./user-mapping.xml"')
	parser.add_argument('-u', '--username',	default='testuser',				help='Username')
	parser.add_argument('-p', '--password',	default='testpass',				help='Password')
	options = parser.parse_args()

	if options.target is None:
		print('Please specify network to scan')
		exit(1)

	### END ARG SETUP ###


	scan = Nmap(options.target)
	scan.start()
	xml_element = gen_config(scan.results(), options.username, options.password)

	n = parseString(ET.tostring(xml_element))
	# print(n.toprettyxml()) # debugging - dump xml to terminal

	with open(options.output, mode='w', encoding='utf-8') as f:
		n.writexml(f, addindent='\t', newl='\n')