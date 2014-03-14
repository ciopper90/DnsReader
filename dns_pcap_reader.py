#! /usr/bin/python
#
# This program decodes DNS packets from the wire or from a capture file
# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core


output_da_risposta_nxdomain=None
output_da_richiesta_dns_nowl=None


def apri_output(uno,due):
    print "apro", uno, " e apro",due
    global output_da_risposta_nxdomain
    output_da_risposta_nxdomain = open(uno,"w")
    #output_da_risposta_nxdomain.write("This Text is going to out file\nLook at it and see\n")
    global output_da_richiesta_dns_nowl
    output_da_richiesta_dns_nowl = open(due,"w")
    #output_da_richiesta_dns_nowl.write("This Text is going to out file\nLook at it and see\n")
    if output_da_richiesta_dns_nowl!=None and output_da_risposta_nxdomain!=None:
        print "aperti!"
        return True
    else:
        return False


def chiudi_file():
    global output_da_risposta_nxdomain
    output_da_risposta_nxdomain.close()

    global output_da_richiesta_dns_nowl
    output_da_richiesta_dns_nowl.close()



type_table={} # This is a lookup table for DNS query types

def initialize_tables() :
    global type_table


# From http://www.networksorcery.com/enp/protocol/dns.htm
    type_table = {1:"A", # IP v4 address, RFC 1035
                  2:"NS", # Authoritative name server, RFC 1035
                  5:"CNAME", # Canonical name for an alias, RFC 1035
                  6:"SOA", # Marks the start of a zone of authority, RFC 1035
                 12:"PTR", # Domain name pointer, RFC 1035
                 13:"HINFO", # Host information, RFC 1035
                 15:"MX", # Mail exchange, RFC 1035
                 28:"AAAA", # IP v6 address, RFC 3596
                 }

def hexify(x):
    "The strings from DNS resolver contain non-ASCII characters - I don't know why. This function investigates that"
    toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)

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
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data)


def decode_dns_response ( rr, response_type ) :
    """This subroutine decodes a DNS response packet. The packet may have more than one rr"""
    r_type = rr.type
    r_data = rr.rdata
    if rr.cls != 1 :
        print ""#"Response is not class IN, might be Hesiod, chaos, or qclass (all of which are anachronisms)"
    print ""#"Response is component", response_type
    if r_type == dpkt.dns.DNS_CNAME :
        print ""#"Response is a CNAME ", r_data," in hex: ", hexify(r_data)
    elif r_type == dpkt.dns.DNS_A :
        print ""#"response is an IPv4 address", socket.inet_ntoa( r_data )
    elif r_type == dpkt.dns.DNS_NS :
        print ""#"Response is a NS name", r_data," in hex: ", hexify(r_data)
    elif r_type == dpkt.dns.DNS_AAAA :
        print ""#"response is an IPv6 address", socket.inet_ntop( socket.AF_INET6, r_data )
    elif r_type == dpkt.dns.DNS_PTR :
        print ""#"response is a hostname from an IP address", r_data, "in hex: ", hexify(r_data)
    else :
        print ""#"Response type is something other than a CNAME, PTR, IPv4 address, or IPv6 address", r_type,
        if r_type in type_table :
            print ""#type_table[r_type]
            print ""#"r-data is ", r_data," in hex: ", hexify(r_data)
        else :
            print ""#"Unknown"


def main() :
    # This code allows this program to run equally well on my laptop and my desktop. I did it this
    # way to demonstrate different interface names. If I was really clever, I'd figure out how to do this
    # under MS-Windows
    #if sys.argv[1] == "-i" :
    #    pc = pcap.pcap( sys.argv[2] )
    #elif sys.argv[1] == "-f" :
    #    pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    #else :
    pc = dpkt.pcap.Reader( open ( "test2.pcap" ) )
    #print """Use -i INTERFACE to [packet capture from an interface.
        #Use -f FILENAME to read a packet capture file"""
        #sys.exit(2)
    initialize_tables()
    vettore_siti_errore=[]
    vettore_siti_ok=[]
    a=apri_output('output_da_risposta_nxdomain','output_da_richiesta_dns_nowl')
    if a!= True:
        return 55555
    #print output_da_risposta_nxdomain,output_da_richiesta_dns_nowl,"vediiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"

    for (src, sport, dst, dport, data ) in udp_iterator(pc) :
        vettore_siti_errore,vettore_siti_ok=dns_core.processa(src,dst,sport,dport,data,vettore_siti_errore,vettore_siti_ok,output_da_risposta_nxdomain,output_da_richiesta_dns_nowl)

    chiudi_file()

    ## in questa lista ho tutte le richieste che mi hanno provocato un fault
    print "Tutte le richieste di siti rilevate che NON ESISTONO sono elencate in questa lista: "
    i=1

    for sito in vettore_siti_errore:
        print i," : ",sito
        i=i+1

    print "Tutte le richieste di siti rilevate che ESISTONO sono elencate in questa lista: "
    i=1


    for sito in vettore_siti_ok:
        print i," : ",sito
        i=i+1


if __name__ == "__main__" :
    main()