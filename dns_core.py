# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess

type_table = {}  # This is a lookup table for DNS query types

dns_whitelist = ['192.168.1.1' , '8.8.8.8']


def initialize_tables():
    global type_table


    # From http://www.networksorcery.com/enp/protocol/dns.htm
    type_table = {1: "A",  # IP v4 address, RFC 1035
                  2: "NS",  # Authoritative name server, RFC 1035
                  5: "CNAME",  # Canonical name for an alias, RFC 1035
                  6: "SOA",  # Marks the start of a zone of authority, RFC 1035
                  12: "PTR",  # Domain name pointer, RFC 1035
                  13: "HINFO",  # Host information, RFC 1035
                  15: "MX",  # Mail exchange, RFC 1035
                  28: "AAAA",  # IP v6 address, RFC 3596
    }



def processa(src, dst, sport, dport, data,vett_siti_err,vett_siti_ok):
    # Uncomment if you want to see all UDP packets
    # print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport
    #if dport == 53 :
    #    # UDP/53 is a DNS query
    #    dns = dpkt.dns.DNS(data)
    #    if dns.opcode != dpkt.dns.DNS_QUERY :
    #        print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode
    #    if dns.qr != dpkt.dns.DNS_Q :
    #        print "A DNS packet was sent to the name server, but dns.qr is not 0 and should be. It is %d" % dns.qr
    #    print "query for ", dns.qd[0].name, "ID is ", dns.id, "dns.qr is ", dns.qr, "query type is ", dns.qd[0].type, type_table[dns.qd[0].type]
    #    print "dns.qd is ", dns.qd
   # print "ricevo vettore siti : ", vettore_siti
    if sport == 53:
        src = socket.inet_ntoa(src)
        dst = socket.inet_ntoa(dst)
        # trasforma da binario a "umano" l'indirizzo ip (quadrupla di interi)
        #print "%s -> %s" % (src, dst)
        # UDP/53 is a DNS response
        try:
            dns = dpkt.dns.DNS(data)
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
                #questo e il caso in cui non ci siano errori
                controlla_dns(src, dst, sport, dport, data)
                #poi bisogna anche controllare se l'url non e malevolo(meglio chiedere al prof qui)

                sito_ok=dns.qd[0].name
                vett_siti_ok.append(sito_ok)
                return vett_siti_err,vett_siti_ok
            ##arriva qui e torna al for, non fai piu nulla qui
            print "responding to ", dns.id, "dns.qr is ", dns.qr, " inviata da '", dst, "' inviata al DNS '", src, "'"
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN:
                print "There is no name in this domain"
            ##stampa l'url ricercat
            ##qui bisogna controllare se risulta essere un url valida oppure no
            sito=dns.qd[0].name
            print "dns.qd is ", sito
            if sito not in list(vett_siti_err):
                vett_siti_err.append(sito)
            print ""
        except Exception:
            print "Errore Data"
            pass
    return vett_siti_err,vett_siti_ok


def controlla_dns(src, dst, sport, dport, data):
    #controlla se il dns e valido oppure no
    ok=0
    for i in dns_whitelist:
        if i == src:
            ok=1
    if ok == 0:
        print "dns non autorizzato " , src , " contattato da ", dst
    return
