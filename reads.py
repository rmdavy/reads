#!/usr/bin/python3

import sqlite3, argparse, os

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
Version 0.1b
Richard Davy 2019
\n
""")

#Write data to file
def DumpHashToFile(outfile, data):
	with open(outfile,"w") as dump:
		dump.write(data)

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

#Setup arg parse and menu structure
parser = argparse.ArgumentParser(description='READS - REsponder Active Database Sifter', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150))

#Create group with hash related options
hgroup = parser.add_argument_group('Hash Related')
hgroup.add_argument('-d', '--domain', dest='domain', default='', type=str, help='-d domainname (filter by domain name, blank to show all)')
hgroup.add_argument('-v', '--version', dest='version', default='3', type=str, help='-v 1/2/3 (1=NetNTLMv1,2=NetNTLMv2,3=NetNTLMv1 & NetNTLMv2')
hgroup.add_argument('-o', '--output', dest='output', default='', type=str, help='-o /tmp/ (directory to output)')
hgroup.add_argument('-n', '--names', dest='names', default='', type=str, help='-n y (to show names without hashes)')

#Create group with Basic Auth and Cleartext related options
cgroup = parser.add_argument_group('Basic Auth/Cleartext Related')
cgroup.add_argument('-b', '--basic', dest='basic', default='', type=str, help='-b y (to show Basic Authentication)')
cgroup.add_argument('-c', '--cleartext', dest='cleartext', default='', type=str, help='-c y (to show Cleartext Authentication)')
cgroup.add_argument('-f', '--filter', dest='filter', default='', type=str, help='-f 192.168.1 (ip to filter)')

#Create group Config options
#DELETE FROM Responder;
cgroup = parser.add_argument_group('Config')
cgroup.add_argument('-p', '--pathtodb', dest='pathtodb', default='/usr/share/responder/Responder.db', type=str, help='-p /usr/share/responder/Responder.db (path to Responder.db - default /usr/share/responder/Responder.db)')
cgroup.add_argument('-edb', '--emptydb', dest='edb', default='', type=str, help='-edb /pathtodb/Responder.db )')

#Parse commandline options
args = parser.parse_args()

#Create dbconnection
cursor = DbConnect(args.pathtodb)
print(args.pathtodb)
banner()

#If condition met delete data from responder.db file
if args.edb!="":
	print ("Cleaning "+args.edb+" of Entries:")
	if os.path.isfile(args.edb):
		answer=input("[!] Are you sure you want to empty "+args.edb+" (y/n) ")
		if answer=="y":
			edbcursor = DbConnect(args.edb)
			res = edbcursor.execute("DELETE FROM Poisoned")
			res = edbcursor.execute("DELETE FROM Responder")
			res = edbcursor.execute("Commit")
			print("[*] Done")
	quit()

#If condition met parse for Basic Auth Details then quit
if args.basic.upper()=="Y":
	print ("Dumping Basic Authentication Details:")
	Basic = GetResponderCompleteBasic(cursor,args.filter)
	print (Basic)
	quit()

#If condition met parse for Cleartext details then quit
if args.cleartext.upper()=="Y":
	print ("Dumping Cleartext Authentication Details:")
	cleartext = GetResponderCompleteClearText(cursor,args.filter)
	print (cleartext)
	quit()

#If verion is 2/3 then get NTLM hash details
if args.version=="2" or args.version=="3":
	print ("Dumping NTLMV2 hashes:")
	v2 = GetResponderCompleteNTLMv2Hash(cursor,args.domain.upper())
	if (len(v2))>0:
		print (v2)
	else:
		print("None Captured\n")

	#If output used write to file
	if len(args.output)>0:
		if (len(v2))>0:
			print ("Writing NTLMV2 hashes to "+args.output+"DumpNTLMv2_5600.txt\n")
			DumpHashToFile(args.output+"DumpNTLMv2_5600.txt", v2)

#If names get user names
if args.names.upper()=="Y":
	#If verion is 2/3 then get NTLMv2 names
	if args.version=="2" or args.version=="3":
		print ("Dumping NTLMV2 Names:")
		v2 = GetResponderCompleteNTLMv2Name(cursor,args.domain.upper())
		if (len(v2))>0:
			print (v2)
		else:
			print("None Captured\n")

		#If output used write to file
		if len(args.output)>0:
			if (len(v2))>0:
				print ("Writing NTLMV2 names to "+args.output+"DumpNTLMv2Names.txt\n")
				DumpHashToFile(args.output+"DumpNTLMv2Names.txt", v2)

#If verion is 2/3 then get NTLM hash details
if args.version=="1" or args.version=="3":
	print ("\nDumping NTLMv1 hashes:")
	v1 = GetResponderCompleteNTLMv1Hash(cursor,args.domain.upper())
	if (len(v1))>0:
		print (v1)
	else:
		print("None Captured\n")

	#If output used write to file
	if len(args.output)>0:   
		if (len(v1))>0:
			print ("Writing NTLMV1 hashes to "+args.output+"DumpNTLMv1_5600.txt\n")
			DumpHashToFile(args.output+"DumpNTLMv1_5500.txt", v1)

#If names get user names
if args.names.upper()=="Y":
	#If verion is 1/3 then get NTLMv1 names
	if args.version=="1" or args.version=="3":
		print ("Dumping NTLMV1 Names:")
		v1 = GetResponderCompleteNTLMv1Name(cursor,args.domain.upper())
		if (len(v1))>0:
			print (v1)
		else:
			print("None Captured\n")

		#If output used write to file
		if len(args.output)>0:
			if (len(v1))>0:
				print ("Writing NTLMV1 names to "+args.output+"DumpNTLMv1Names.txt\n")
				DumpHashToFile(args.output+"DumpNTLMv1Names.txt", v1)