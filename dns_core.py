# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import csv
import re
from datetime import datetime






type_table = {}  # This is a lookup table for DNS query types
dns_whitelist = []
malevoli={}
output_R_ok=""
output_R_no=""
output_Q=""

#inizio inizializzazioni
def open_file():
    global output_R_ok
    output_R_ok = open("output_R_ok","w")
    global output_R_no
    output_R_no = open("output_R_no","w")
    global output_Q
    output_Q = open("output_Q","w")
    if output_R_ok!=None and output_R_no!=None and output_Q!=None:

        ##metto un intestazione ai file per capire cosa è e com'è
        line="timestamp, Client, Nameserver, HostNameRisoltoOK"
        scrivi(line,output_R_ok)
        line="timestamp, Client, Nameserver,HostNameRichiestoDaRisolvereNXDOMAIN"
        scrivi(line,output_R_no)
        line="timestamp, Client, Nameserver, HostNameRichiestoDaRisolvere"
        scrivi(line,output_Q)

        return True
    else:
        return False

def close_file():
    global output_R_ok
    output_R_ok.close()
    global output_R_no
    output_R_no.close()
    global output_Q
    output_Q.close()

def scrivi(str,file):
    str=str[:]+"\n"
    file.write(str)

def loadDns():
    global dns_whitelist
    with open('dns_permessi.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        for i in reader:
             dns_whitelist.append(i[0])

def loadSitiMalevoli():
    global malevoli
    malevoli={}
    with open('name_malevoli.csv', 'rb') as csvfile:
		reader=csv.reader(csvfile, delimiter=',', quotechar='|')
		#reader=str(reader)[0]
		for i in reader:

			if 3<len(i):

				i=i[3].replace("\"", "")
				#print i
				if not malevoli.has_key(i) and i != "-":
					#print i
					malevoli[i]=i



def initialize_tables():
    global type_table
    type_table = {1: "A",  # IP v4 address, RFC 1035
                  2: "NS",  # Authoritative name server, RFC 1035
                  5: "CNAME",  # Canonical name for an alias, RFC 1035
                  6: "SOA",  # Marks the start of a zone of authority, RFC 1035
                  12: "PTR",  # Domain name pointer, RFC 1035
                  13: "HINFO",  # Host information, RFC 1035
                  15: "MX",  # Mail exchange, RFC 1035
                  28: "AAAA",  # IP v6 address, RFC 3596
    }

#fine inizializzazioni

def udp_iterator(pc):
    """pc is a pcap.pcap object that listens to the network and returns a packet object when it hears a packet go by"""
    for ts, pkt in pc:
        # parse the packet. Decode the ethertype. If it is IP (IPv4) then process it further
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP :
            ip = eth.data
            # If the IP protocol is UDP, then process it further
            if ip.p == dpkt.ip.IP_PROTO_UDP :
                udp = ip.data
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data,ts)
            elif ip.p ==dpkt.ip.IP_PROTO_TCP:
                print "tcp"



def reader(pc):
    open_file()
    for (src, sport, dst, dport, data,timestamp ) in udp_iterator(pc) :
        processa(src,dst,sport,dport,data,timestamp)
    close_file()

def processa(src, dst, sport, dport, data,timestamp):
    if len(dns_whitelist) == 0 or len(malevoli)==0:
        loadDns()
        loadSitiMalevoli()

    try:
        sorgente=socket.inet_ntoa(src)
        destinazione = socket.inet_ntoa(dst)
        timestamp="{:.9f}".format(timestamp)
        timestamp = str(datetime.fromtimestamp( float(timestamp) ))

        dns = dpkt.dns.DNS(data)

        if dns.qr == dpkt.dns.DNS_Q:#dport == 53 :
            # UDP/53 is a DNS query
            #richiesta
            #client = sorgente
            #nameserver = destinazione

            if destinazione not in dns_whitelist:
                ##NB. il prof vuole SEMPRE lo stesso ordine
                ## timestamp, client, nameserver, hostname(darisolvere)
                #print "%s: %f " % ( "quiiiiiiiiiiiiiiiiiiiiii tempoooo", timestamp)
                line=timestamp+", "+str(sorgente) +", "+str(destinazione)+", "+dns.qd[0].name
                scrivi(line,output_Q)

        if dns.qr == dpkt.dns.DNS_R:#sport == 53:
            # UDP/53 is a DNS response
            #nameserver = sorgente
            #client = destinazione
            ##NB. il prof vuole SEMPRE lo stesso ordine
            ## timestamp, client, nameserver, hostname(risolto)

            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
                line=timestamp+", "+str(destinazione) +", "+str(sorgente)+", "+str(dns.qd[0].name)
                sito= dns.qd[0].name
                result = re.match("(.)*.?unimo(re)?.it$", sito,re.IGNORECASE)

                if result == None and not malevoli.has_key(sito) :
                                ##è una ricerca precisa di chiave... quindi non è ottima me funziona
                    print sito
                    ##qui loggo i siti leciti che NON fanno parte di unimore
                    scrivi(line,output_R_ok)
                else:
                    if malevoli.has_key(sito) :
                        ## se è un sito malevolo che è contenuto in quella lista
                        print "Sito ",sito, "è una minaccia"

                return
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN:
                line=timestamp+", "+str(destinazione) +", "+str(sorgente)+", "+str(dns.qd[0].name)
                sito= dns.qd[0].name
                result = re.match("(.)*.local$|(.)*.?unimo(re)?.it$", sito,re.IGNORECASE)

                if result == None :
                    ##anche qui,stampo solo i siti che risultano errati ma che NON sono universitari
                    scrivi(line,output_R_no)

    except Exception:
        print "Errore Data"

    return


##deprecata e integrata sopra
#def controlla_dns(nameserver, client, sport, dport, data):
#    "controlla se il dns e valido oppure no"
#    if nameserver not in dns_whitelist:
#        #timestamp,dst,src,namedomain,address
#        print client,", ",nameserver,", "
#    return
