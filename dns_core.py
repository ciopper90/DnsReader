# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import csv
import re
from datetime import datetime
from scapy.all import *
import sys
import os
import fcntl
import time



type_table = {}  # This is a lookup table for DNS query types
dns_whitelist = []
regexp = ''
#regexp = []
dns_blacklist= set()
malevoli={}
output_R_ok=""
output_R_no=""
output_Q=""
devia_verso=''
crea_risposta=''
da_porta=''

#inizio inizializzazioni
def open_file(nome_out):
    global output_R_ok
    output_R_ok = open(nome_out+"_R_ok.csv","w")
    global output_R_no
    output_R_no = open(nome_out+"_R_no.csv","w")
    global output_Q
    output_Q = open(nome_out+"_Q.csv","w")
    global output_ALARM
    output_ALARM = open(nome_out+"_ALARM.csv","w")

    if output_R_ok!=None and output_R_no!=None and output_Q!=None and output_ALARM!=None:

        ##metto un intestazione ai file per capire cosa Ã¨ e com'Ã¨
        line="timestamp, Client, Nameserver, HostNameRisoltoOK"
        scrivi(line,output_R_ok)
        line="timestamp, Client, Nameserver,HostNameRichiestoDaRisolvereNXDOMAIN"
        scrivi(line,output_R_no)
        line="timestamp, Client, Nameserver, HostNameRichiestoDaRisolvere"
        scrivi(line,output_Q)
        line="timestamp, Client, Nameserver, MotivoAllarme"
        scrivi(line,output_ALARM)

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
    global output_ALARM
    output_ALARM.close()

def scrivi(str,file):
    str=str[:]+"\n"
    file.write(str)
    file.flush()

def loadDns_black():
    global dns_blacklist
    with open('dns_proibiti.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        for i in reader:
             dns_blacklist.add(socket.inet_aton(i[0])) # prende una stringa e la trasforma in numero binario!
                                                          # faccio controllo hash ultra rapido


def loadDns_white():
    global dns_whitelist
    with open('dns_permessi.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        for i in reader:
             dns_whitelist.append(socket.inet_aton(i[0]))

def loadRegExp():
    global regexp

    with open('regexp.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        for i in reader:
            if regexp == '':
                regexp = i[0]
            else:
                regexp = regexp + "|" + i[0]
    regexp = re.compile(regexp)

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

def general_iterator(pc):
    """pc is a pcap.pcap object that listens to the network and returns a packet object when it hears a packet go by"""
    fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:

        for ts, pkt in pc:   ##il fatto che l'uscita non sia responsive con il RETURN Ã¨ dovuto al fatto che qui Ã¨ in attesa di qualcosa!!
            # parse the packet. Decode the ethertype. If it is IP (IPv4) then process it further

            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP :
                ip = eth.data
                # If the IP protocol is UDP, then process it further
                if ip.p == dpkt.ip.IP_PROTO_UDP :
                        udp = ip.data
                        # Pass the IP addresses, source port, destination port, and data back to the caller.
                        yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data, ts)
                elif ip.p ==dpkt.ip.IP_PROTO_TCP:
                        tcp=ip.data
                        #print "tcp",socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport, tcp.data, ts
                        yield ( ip.src, tcp.sport, ip.dst, tcp.dport, tcp.data, ts)
    except KeyboardInterrupt:
        print " Esco"


def reader(pc,nome_out,crea_risp,devia,porta):
    open_file(nome_out)
    global devia_verso
    devia_verso=devia
    print devia_verso
    if crea_risp==0:
        print "Non creo risposte, solo logging"
    elif crea_risp==1:
         print "Creo risposte, rimando verso: ",devia_verso
    elif crea_risp==2:
         print "Rispondo No Such Domain"

    processati=0;
    global errati
    errati=0
    global crea_risposta
    crea_risposta=crea_risp
    global da_porta
    da_porta=porta

    conf.verb = 0
    print "Premi un INVIO o CTRL+C per terminare , altrimenti aspetta"

    if len(dns_whitelist) == 0 or len(malevoli)==0 or len(dns_blacklist)==0:
        loadDns_white()
        loadDns_black()
        loadRegExp()

    for (src, sport, dst, dport, data,timestamp ) in general_iterator(pc) : ##il fatto che l'uscita non sia responsive con il RETURN Ã¨ dovuto al fatto che qui Ã¨ in attesa di qualcosa!!
        try:
            processa(src,dst,sport,dport,data,timestamp)
            processati=processati+1
            try:
                stdin = sys.stdin.read()
                if "\n" in stdin or "\r" in stdin:
                    print "terminato prima della Conclusione naturale"
                    break
            except IOError:
                pass
        except KeyboardInterrupt:
            break

    #processati=0

    close_file()

    print "Processati Pacchetti in numero: ",processati, " e pacchetti che danno errore  ",errati

def processa(src, dst, sport, dport, data,timestamp):
#        loadSitiMalevoli()

    try:
        sorgente=socket.inet_ntoa(src)
        destinazione = socket.inet_ntoa(dst)
        timestamp="{:.9f}".format(timestamp)
        timestamp = str(datetime.fromtimestamp( float(timestamp) ))

        try:
            dns = dpkt.dns.DNS(data)
        except (IndexError, dpkt.dpkt.UnpackError) as x:
            print x
            return

        if dns.qr == dpkt.dns.DNS_Q:#dport == 53 :
            # UDP/53 is a DNS query
            #richiesta
            if dst in dns_blacklist:
                ## Ã¨ un allarme!
                ##lascio in binario in quanto faccio la comparazione in binario Ã¨ ultrarapida

                if crea_risposta==1:
                    manda_risposta_fantoccio(dns,sorgente,destinazione,sport,dport)
                if crea_risposta==2:
                    manda_risposta_NXD(dns,sorgente,destinazione,sport,dport)
                ##ricordo che la src sarÃ  il destinatario e la dst sarÃ  la sorgente

                line=timestamp+", "+str(sorgente) +", "+str(destinazione)+", DomandaADnsNonLecito"
                scrivi(line,output_ALARM)

            if dst not in dns_whitelist:
                line=timestamp+", "+str(sorgente) +", "+str(destinazione)+", "+dns.qd[0].name
                scrivi(line,output_Q)

        if dns.qr == dpkt.dns.DNS_R:
            # UDP/53 is a DNS response
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
                line=timestamp+", "+str(destinazione) +", "+str(sorgente)+", "+str(dns.qd[0].name)
                sito= dns.qd[0].name
                result = regexp.match(sito,re.IGNORECASE)

                if result == None :#and not malevoli.has_key(sito) :
                    ##Ã¨ una ricerca precisa di chiave... quindi non Ã¨ ottima me funziona
                    ##qui loggo i siti leciti che NON fanno parte di unimore
                    scrivi(line,output_R_ok)
                else:
                    asd=1

                if src in dns_blacklist:
                    ## Ã¨ un allarme!
                    ##lascio in binario in quanto faccio la comparazione in binario Ã¨ ultrarapida
                    line=timestamp+", "+str(destinazione) +", "+str(sorgente)+", RispostaDaDnsNonLecito"
                    scrivi(line,output_ALARM)

                return
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN:
                line=timestamp+", "+str(destinazione) +", "+str(sorgente)+", "+str(dns.qd[0].name)
                sito= dns.qd[0].name
                result = regexp.match(sito,re.IGNORECASE)
                if result == None :
                    ##anche qui,stampo solo i siti che risultano errati ma che NON sono universitari
                    scrivi(line,output_R_no)

    except dpkt.dpkt.NeedData, KeyboardInterrupt:
        global errati
        errati=errati+1

    return


def manda_risposta_fantoccio(dns,src,dst,sport,dport):
    #devo leggere tutti i dati dal pacchetto dns passato alla funzione
    try:
        mypacket = scapy.all.IP(dst=src,src=dst)/\
                   scapy.all.UDP(dport=sport, sport=dport)/\
                   scapy.all.DNS(id=dns.id, aa=1, qr=1, qdcount=1, qd=scapy.all.DNSQR(qtype='A', qname=dns.qd[0].name), \
                   an=scapy.all.DNSRR(rrname=dns.qd[0].name,  ttl=300, rdata=devia_verso))
        scapy.all.send(mypacket,iface=da_porta)
    except Exception as x:
        print x


def manda_risposta_NXD(dns,src,dst,sport,dport):
    ## qui ho giÃ  dst e src giusti da usare
    try:
        mypacket = scapy.all.IP(dst=src,src=dst)/\
                   scapy.all.UDP(dport=sport, sport=dport)/\
                   scapy.all.DNS(id=dns.id, aa=1, qr=1, qdcount=1, qd=scapy.all.DNSQR(qtype='A', qname=dns.qd[0].name), rcode=3)
        scapy.all.send(mypacket,iface=da_porta)
    except Exception as x:
        print x
    #print "risposta NXD mandata"
