# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import csv


type_table = {}  # This is a lookup table for DNS query types

dns_whitelist = []

def scrivi(str,file):
    #print "voglio scrivere ",str," su file ",file
    str=str[:]+"\n"
    file.write(str)


def loadDns():
    #funzione per il caricamento dinamico dei dns(va poi implementato)
    global dns_whitelist
    with open('dns_permessi.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        reader=list(reader)[0]
        for i in reader:
            dns_whitelist.append(i)

    #print dns_whitelist , "questa è la whitelisttttttttttttttttttttttttttttttttttttttttttttttttttt"

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



def processa(src, dst, sport, dport, data,vett_siti_err,vett_siti_ok,output_da_risposta_nxdomain,output_da_richiesta_dns_nowl):
    if len(dns_whitelist) == 0:
        loadDns()

    try:
        client = socket.inet_ntoa(src)
        nameserver = socket.inet_ntoa(dst)
        dns = dpkt.dns.DNS(data)
        if dns.qr == dpkt.dns.DNS_Q:#dport == 53 :
            # UDP/53 is a DNS query
            if nameserver not in dns_whitelist:
                line="timestamp, "+str(client) +", "+str(nameserver)+", domain"
               # print line,"URCAAAAAAAAAAAAAAAAAAAAAAAAAAA",nameserver," non è in ",dns_whitelist
                scrivi(line,output_da_richiesta_dns_nowl)

        if dns.qr == dpkt.dns.DNS_R:#sport == 53:
            # UDP/53 is a DNS response
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
                #questo e il caso in cui non ci siano errori
                controlla_dns(nameserver, client, sport, dport, data)
                #poi bisogna anche controllare se l'url non e malevolo(meglio chiedere al prof qui)

                sito= dns.qd[0].name

                if sito != " fa regex qui non permesse":


######stampa per debug grossolano########
######################################################################
                    print "RISPOSTA a richiesta risoluzione esistente e permessa"
                    sito_ok=sito
                    if sito_ok not in vett_siti_ok:
                        vett_siti_ok.append(sito_ok)
####################################################################
                else:
                    print "RISPOSTA dove il sito richiesto esistente è noto come non sicuro"

                return vett_siti_err,vett_siti_ok
            ##arriva qui e torna al for, non fai piu nulla qui
            #print "responding to ", dns.id, "dns.qr is ", dns.qr, " inviata da '", client, "' inviata al DNS '", nameserver, "'"
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN:
                line="timestamp, "+str(client) +", "+str(nameserver)+", "+str(dns.qr) +", "+str(dns.qd[0].name)
                #print line

                sito= dns.qd[0].name
                sito_ko=""
                if sito == " fa regex qui che è unimore.it o unimo.it":
                    print "RISPOSTA A RICHIESTA CON NXDOMAIN È ok"

                else:
                    print "RISPOSTA A richista CON nxdomain è a rischio "
                    scrivi(line,output_da_risposta_nxdomain)
                    sito_ko=sito

######stampa per debug grossolano########
###########################################################

                if sito_ko not in vett_siti_err and sito_ko!="":
                    vett_siti_err.append(sito_ko)
###########################################################

    except Exception:
        print "Errore Data"

    return vett_siti_err,vett_siti_ok


def controlla_dns(nameserver, client, sport, dport, data):
    #controlla se il dns e valido oppure no
    if nameserver not in dns_whitelist:
        #timestamp,dst,src,namedomain,address
        print client,", ",nameserver,", "
    return
