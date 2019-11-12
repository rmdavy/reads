# reads
REsponder Active Database Sifter

Provides some command line switch improvements/additional options over the dumphashes.py which gets bundled with responder.

usage: reads.py [-h] [-d DOMAIN] [-v VERSION] [-o OUTPUT] [-n NAMES] [-e EXCLUDEMACHINEACCOUNTS] [-b BASIC] [-c CLEARTEXT] [-f FILTER] [-ps POISON]
                [-psf POISONFILTER] [-po POISONOUTPUT] [-p PATHTODB] [-edb EDB]

READS - REsponder Active Database Sifter

optional arguments:
  -h, --help        show this help message and exit

Hash Related:
  -d DOMAIN, --domain DOMAIN
                    -d domainname (filter by domain name, blank to show all)
  -v VERSION, --version VERSION
                    -v 1/2/3 (1=NetNTLMv1,2=NetNTLMv2,3=NetNTLMv1 & NetNTLMv2
  -o OUTPUT, --output OUTPUT
                    -o /tmp/ (directory to output)
  -n NAMES, --names NAMES
                    -n y (to show names without hashes)
  -e EXCLUDEMACHINEACCOUNTS, --excludemachineaccounts EXCLUDEMACHINEACCOUNTS
                    -e y (excludes machine accounts)

Basic Auth/Cleartext Related:
  -b BASIC, --basic BASIC
                    -b y (to show Basic Authentication)
  -c CLEARTEXT, --cleartext CLEARTEXT
                    -c y (to show Cleartext Authentication)
  -f FILTER, --filter FILTER
                    -f 192.168.1 (ip to filter)

Poison Related:
  -ps POISON, --poison POISON
                    -ps y (to show Poisoned ips)
  -psf POISONFILTER, --poisonfilter POISONFILTER
                    -psf 192.168.1 (ip to filter)
  -po POISONOUTPUT, --poisonoutput POISONOUTPUT
                    -po /tmp/ (directory to output)

Config:
  -p PATHTODB, --pathtodb PATHTODB
                    -p /usr/share/responder/Responder.db (path to Responder.db - default /usr/share/responder/Responder.db)
  -edb EDB, --emptydb EDB
                    -edb /pathtodb/Responder.db )

