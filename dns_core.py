# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess

type_table = {}  # This is a lookup table for DNS query types


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
        dns = dpkt.dns.DNS(data)
        if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
            sito_ok=dns.qd[0].name
            vett_siti_ok.append(sito_ok)
            return vett_siti_err,vett_siti_ok
        ##arriva qui e torna al for, non fai piu nulla qui
        print "responding to ", dns.id, "dns.qr is ", dns.qr, " inviata da '", dst, "' inviata al DNS '", src, "'"
        #if dns.qr != dpkt.dns.DNS_R:
        #    print ""#"A DNS packet was received from a name server, but dns.qr is not 1 and should be. It is %d" % dns.qr
        #if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR:
            #print ""#"Response has no error"
        if dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN:
            print "There is no name in this domain"
        #else:
        #    print ""  #"Response is something other than NOERR or NXDOMAIN %d - this software is incomplete" % dns.get_rcode()
        #print ""  #"The response packet has %d RRs" % len(dns.an)
        # Decode the RR records in the NS section
        for rr in dns.ns:
            decode_dns_response(rr, "NS")
        # Decode the answers in the DNS answer
        for rr in dns.an:
            decode_dns_response(rr, "AN")
        # Decode the additional responses
        for rr in dns.ar:
            decode_dns_response(rr, "AR")
        ##stampa l'url ricercat
        ##qui bisogna controllare se risulta essere un url valida oppure no
        sito=dns.qd[0].name
        print "dns.qd is ", sito

    #    print "vettore siti e' ", vettore_siti
        if sito not in list(vett_siti_err):
            vett_siti_err.append(sito)
        print ""
    return vett_siti_err,vett_siti_ok


def hexify(x):
    "The strings from DNS resolver contain non-ASCII characters - I don't know why. This function investigates that"
    toHex = lambda x: "".join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)


def udp_iterator(pc):
    """pc is a pcap.pcap object that listens to the network and returns a packet object when it hears a packet go by"""
    for ts, pkt in pc:
        # parse the packet. Decode the ethertype. If it is IP (IPv4) then process it further
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            # If the IP protocol is UDP, then process it further
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data)


def decode_dns_response(rr, response_type):
    """This subroutine decodes a DNS response packet. The packet may have more than one rr"""
    r_type = rr.type
    r_data = rr.rdata
    #if rr.cls != 1:
    #    print ""  #"Response is not class IN, might be Hesiod, chaos, or qclass (all of which are anachronisms)"
    #print ""  #"Response is component", response_type
    #if r_type == dpkt.dns.DNS_CNAME:
    #    print ""  #"Response is a CNAME ", r_data," in hex: ", hexify(r_data)
    #elif r_type == dpkt.dns.DNS_A:
    #    print ""  #"response is an IPv4 address", socket.inet_ntoa( r_data )
    #elif r_type == dpkt.dns.DNS_NS:
    #    print ""  #"Response is a NS name", r_data," in hex: ", hexify(r_data)
    #elif r_type == dpkt.dns.DNS_AAAA:
    #    print ""  #"response is an IPv6 address", socket.inet_ntop( socket.AF_INET6, r_data )
    #elif r_type == dpkt.dns.DNS_PTR:
    #    print ""  #"response is a hostname from an IP address", r_data, "in hex: ", hexify(r_data)
    #else:
    #    print ""  #"Response type is something other than a CNAME, PTR, IPv4 address, or IPv6 address", r_type,
    #    if r_type in type_table:
    #        print ""  #type_table[r_type]
    #        print ""  #"r-data is ", r_data," in hex: ", hexify(r_data)
    #    else:
    #        print ""  #"Unknown"
