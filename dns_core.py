# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import csv


type_table = {}  # This is a lookup table for DNS query types

dns_whitelist = []


def loadDns():
    #funzione per il caricamento dinamico dei dns(va poi implementato)
    global dns_whitelist
    #dns_whitelist = ['192.168.1.1' , '8.8.8.8']
    with open('dns_permessi.csv', 'rb') as csvfile:
        dns_whitelist = list(csv.reader(csvfile, delimiter=',', quotechar='|'))[0]
        #print " è stato letto: ",dns_whitelist," poiiiiiiiiiiiiiiiiiii"
        #for row in dns_whitelist:
        #    print row

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
    if len(dns_whitelist) == 0:
        loadDns()

    try:

        dns = dpkt.dns.DNS(data)
        if dns.qr == dpkt.dns.DNS_Q:#dport == 53 :
            # UDP/53 is a DNS query
            # quindi è una domanda query


                client = socket.inet_ntoa(src)
                nameserver = socket.inet_ntoa(dst)
                if dns.opcode != dpkt.dns.DNS_QUERY :
                    print ""#"A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode

                if nameserver not in dns_whitelist:
                    print "richiesta a dns",nameserver," non in whitelist da parte di",client," lista dns",dns_whitelist



        if dns.qr == dpkt.dns.DNS_R:#sport == 53:
            # UDP/53 is a DNS response
            ## qui sono risposte

            # trasforma da binario a "umano" l'indirizzo ip (quadrupla di interi)
            nameserver = socket.inet_ntoa(src)
            client = socket.inet_ntoa(dst)


            dns = dpkt.dns.DNS(data)
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
                #questo e il caso in cui non ci siano errori
                controlla_dns(nameserver, client, sport, dport, data)
                #poi bisogna anche controllare se l'url non e malevolo(meglio chiedere al prof qui)

                sito_ok=dns.qd[0].name
                vett_siti_ok.append(sito_ok)
                return vett_siti_err,vett_siti_ok
            ##arriva qui e torna al for, non fai piu nulla qui
            print "responding to ", dns.id, "dns.qr is ", dns.qr, " inviata da '", client, "' inviata al DNS '", nameserver, "'"
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

    return vett_siti_err,vett_siti_ok


def controlla_dns(nameserver, client, sport, dport, data):
    #controlla se il dns e valido oppure no
    ok=0
    if nameserver not in dns_whitelist:
        print "dns non autorizzato " , nameserver , " contattato da ", client, " non presente in ", dns_whitelist

    return
