#!/usr/bin/python3

import sqlite3, argparse, os, socket, string

def banner():
	print ("""
\n
 /$$$$$$$  /$$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$ 
| $$__  $$| $$_____/ /$$__  $$| $$__  $$ /$$__  $$
| $$  \ $$| $$      | $$  \ $$| $$  \ $$| $$  \__/
| $$$$$$$/| $$$$$   | $$$$$$$$| $$  | $$|  $$$$$$ 
| $$__  $$| $$__/   | $$__  $$| $$  | $$ \____  $$
| $$  \ $$| $$      | $$  | $$| $$  | $$ /$$  \ $$
| $$  | $$| $$$$$$$$| $$  | $$| $$$$$$$/|  $$$$$$/
|__/  |__/|________/|__/  |__/|_______/  \______/ 

REsponder Active Database Sifter
Version 0.1c
Richard Davy 2019
\n
""")

#Write data to file
def WriteToFile(outfile, data, ema):
	f = open(outfile, "w")
	for line in data.splitlines():
		if ema.upper()=='Y':	
			if not "$" in line:
				f.write(line+"\n")
		else:
			f.write(line+"\n")
	f.close()

def PrintToScreen(data, ema):
	for line in data.splitlines():
		if ema.upper()=='Y':	
			if not "$" in line:
				print(line)
		else:
			print(line)
	
#Connect to db
def DbConnect(pathtodb):
	#Assumes that this will be run from responder directory
	cursor = sqlite3.connect(pathtodb)
	return cursor

#Extract NTLMv2 hashes from DB
def GetResponderCompleteNTLMv2Hash(cursor, domain):
	res = cursor.execute("SELECT fullhash FROM Responder WHERE user LIKE " + "\'%"+domain+"%\'" + "AND type LIKE '%v2%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'
	return Output

#Extract NTLMv2 names from DB
def GetResponderCompleteNTLMv2Name(cursor, domain):
	res = cursor.execute("SELECT user FROM Responder WHERE user LIKE " + "\'%"+domain+"%\'" + "AND type LIKE '%v2%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'
	return Output

#Extract NTLMv1 hashes from DB
def GetResponderCompleteNTLMv1Hash(cursor, domain):
	res = cursor.execute("SELECT fullhash FROM Responder WHERE user LIKE " + "\'%"+domain+"%\'" + "AND type LIKE '%v1%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'
	return Output

#Extract NTLMv1 names from DB
def GetResponderCompleteNTLMv1Name(cursor, domain):
	res = cursor.execute("SELECT user FROM Responder WHERE user LIKE " + "\'%"+domain+"%\'" + "AND type LIKE '%v1%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'
	return Output

#Extract Basic Auth details from DB
def GetResponderCompleteBasic(cursor,ipfilter):
	res = cursor.execute("SELECT user,cleartext,client FROM Responder WHERE type LIKE 'Basic' AND client LIKE " + "\'%"+ipfilter+"%\'")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'+'{0}'.format(row[1])+'\n'+'{0}'.format(row[2])+'\n\n'
	return Output

#Extract clear text details from DB
def GetResponderCompleteClearText(cursor,ipfilter):
	res = cursor.execute("SELECT user,cleartext,client FROM Responder WHERE type LIKE 'cleartext' AND client LIKE " + "\'%"+ipfilter+"%\'")
	Output = ""
	for row in res.fetchall():
		Output += '{0}'.format(row[0])+'\n'+'{0}'.format(row[1])+'\n'+'{0}'.format(row[2])+'\n\n'
	return Output

#Extract Poisoned Details from DB
def GetPoisoned(cursor,ipfilter):
	res = cursor.execute("SELECT DISTINCT senttoip, poisoner from Poisoned WHERE senttoip LIKE " + "\'%"+ipfilter+"%\' ORDER BY SentToIp")
	Output = ""
	for row in res.fetchall():
		#Get Reverse DNS Lookup Information		
		name,alias,addresslist = (lookup('{0}'.format(row[0])))
		#Output DNS, IP, Poison Type
		Output += str(name)+','+'{0}'.format(row[0])+','+'{0}'.format(row[1])+'\n'
	return Output

#Perform Reverse DNS Lookup
def lookup(addr):
	try:
		return socket.gethostbyaddr(addr)
	except socket.herror:
		return None, None, None

#Setup arg parse and menu structure
parser = argparse.ArgumentParser(description='READS - REsponder Active Database Sifter', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150))

#Create group with hash related options
hgroup = parser.add_argument_group('Hash Related')
hgroup.add_argument('-d', '--domain', dest='domain', default='', type=str, help='-d domainname (filter by domain name, blank to show all)')
hgroup.add_argument('-v', '--version', dest='version', default='3', type=str, help='-v 1/2/3 (1=NetNTLMv1,2=NetNTLMv2,3=NetNTLMv1 & NetNTLMv2')
hgroup.add_argument('-o', '--output', dest='output', default='', type=str, help='-o /tmp/ (directory to output)')
hgroup.add_argument('-n', '--names', dest='names', default='', type=str, help='-n y (to show names without hashes)')
hgroup.add_argument('-e', '--excludemachineaccounts', dest='excludemachineaccounts', default='', type=str, help='-e y (excludes machine accounts)')

#Create group with Basic Auth and Cleartext related options
cgroup = parser.add_argument_group('Basic Auth/Cleartext Related')
cgroup.add_argument('-b', '--basic', dest='basic', default='', type=str, help='-b y (to show Basic Authentication)')
cgroup.add_argument('-c', '--cleartext', dest='cleartext', default='', type=str, help='-c y (to show Cleartext Authentication)')
cgroup.add_argument('-f', '--filter', dest='filter', default='', type=str, help='-f 192.168.1 (ip to filter)')

#Create group Poisoned options
egroup = parser.add_argument_group('Poison Related')
egroup.add_argument('-ps', '--poison', dest='poison', default='', type=str, help='-ps y (to show Poisoned ips)')
egroup.add_argument('-psf', '--poisonfilter', dest='poisonfilter', default='', type=str, help='-psf 192.168.1 (ip to filter)')
egroup.add_argument('-po', '--poisonoutput', dest='poisonoutput', default='', type=str, help='-po /tmp/ (directory to output)')

#Create group Config options
ggroup = parser.add_argument_group('Config')
ggroup.add_argument('-p', '--pathtodb', dest='pathtodb', default='/usr/share/responder/Responder.db', type=str, help='-p /usr/share/responder/Responder.db (path to Responder.db - default /usr/share/responder/Responder.db)')
ggroup.add_argument('-edb', '--emptydb', dest='edb', default='', type=str, help='-edb /pathtodb/Responder.db )')

#Parse commandline options
args = parser.parse_args()

banner()

#Create dbconnection
if os.path.isfile(args.pathtodb):
	cursor = DbConnect(args.pathtodb)
else:
	print("[!] Database "+args.pathtodb+" could not be found...")
	quit()

#If condition met delete data from responder.db file
if args.edb!="":
	print ("Clean "+args.edb+" of entries:")
	if os.path.isfile(args.edb):
		answer=input("[!] Are you sure you want to empty "+args.edb+" (y/n) ")
		if answer=="y":
			edbcursor = DbConnect(args.edb)
			res = edbcursor.execute("DELETE FROM Poisoned")
			res = edbcursor.execute("DELETE FROM Responder")
			res = edbcursor.execute("Commit")
			print("[*] Done")
	quit()

#Check status of NetBIOS-NS
#wmic nicconfig get caption,index,TcpipNetbiosOptions
#Disable NetBIOS-NS on all active adapters
#wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2

#Disable LLMNR
#REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
#REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f

#If condition met parse for Poisoned Details then quit
if args.poison.upper()=="Y":
	print ("[*] Poisoned Details:\n")
	print ("Reverse DNS, IP, Poisoner type")
	Basic = GetPoisoned(cursor,args.poisonfilter)
	print (Basic)
	if len(args.poisonoutput)>0:
		print ("[*] Writing Poisoned hosts to "+args.poisonoutput+"poisonoutput.csv\n")
		WriteToFile(args.poisonoutput+"poisonoutput.csv", Basic, "")
	quit()

#If condition met parse for Basic Auth Details then quit
if args.basic.upper()=="Y":
	print ("[*] Dumping Basic Authentication Details:")
	Basic = GetResponderCompleteBasic(cursor,args.filter)
	print (Basic)
	quit()

#If condition met parse for Cleartext details then quit
if args.cleartext.upper()=="Y":
	print ("[*] Dumping Cleartext Authentication Details:")
	cleartext = GetResponderCompleteClearText(cursor,args.filter)
	print (cleartext)
	quit()

#If verion is 2/3 then get NTLM hash details
if args.version=="2" or args.version=="3":
	print ("[*] Dumping NTLMV2 hashes:")
	v2 = GetResponderCompleteNTLMv2Hash(cursor,args.domain.upper())
	if (len(v2))>0:
		PrintToScreen(v2,args.excludemachineaccounts)
	else:
		print("[!] None Captured\n")

	#If output used write to file
	if len(args.output)>0:
		if (len(v2))>0:
			print ("\n[*] Writing NTLMV2 hashes to "+args.output+"DumpNTLMv2_5600.txt\n")
			WriteToFile(args.output+"DumpNTLMv2_5600.txt", v2, args.excludemachineaccounts)

#If names get user names
if args.names.upper()=="Y":
	#If verion is 2/3 then get NTLMv2 names
	if args.version=="2" or args.version=="3":
		print ("\n[*] Dumping NTLMV2 Names:")
		v2 = GetResponderCompleteNTLMv2Name(cursor,args.domain.upper())
		if (len(v2))>0:
			PrintToScreen(v2,args.excludemachineaccounts)
		else:
			print("[!] None Captured\n")

		#If output used write to file
		if len(args.output)>0:
			if (len(v2))>0:
				print ("\n[*] Writing NTLMV2 names to "+args.output+"DumpNTLMv2Names.txt\n")
				WriteToFile(args.output+"DumpNTLMv2Names.txt", v2, args.excludemachineaccounts)

#If verion is 2/3 then get NTLM hash details
if args.version=="1" or args.version=="3":
	print ("\n[*] Dumping NTLMv1 hashes:")
	v1 = GetResponderCompleteNTLMv1Hash(cursor,args.domain.upper())
	if (len(v1))>0:
		PrintToScreen(v1,args.excludemachineaccounts)
	else:
		print("[!] None Captured\n")

	#If output used write to file
	if len(args.output)>0:   
		if (len(v1))>0:
			print ("\n[*] Writing NTLMV1 hashes to "+args.output+"DumpNTLMv1_5600.txt\n")
			WriteToFile(args.output+"DumpNTLMv1_5500.txt", v1, args.excludemachineaccounts)

#If names get user names
if args.names.upper()=="Y":
	#If verion is 1/3 then get NTLMv1 names
	if args.version=="1" or args.version=="3":
		print ("\n[*] Dumping NTLMV1 Names:")
		v1 = GetResponderCompleteNTLMv1Name(cursor,args.domain.upper())
		if (len(v1))>0:
			PrintToScreen(v1,args.excludemachineaccounts)
		else:
			print("[!] None Captured\n")

		#If output used write to file
		if len(args.output)>0:
			if (len(v1))>0:
				print ("\n[*] Writing NTLMV1 names to "+args.output+"DumpNTLMv1Names.txt\n")
				WriteToFile(args.output+"DumpNTLMv1Names.txt", v1, args.excludemachineaccounts)