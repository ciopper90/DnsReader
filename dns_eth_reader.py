import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core


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
            else:
                print "tcp"

def main() :
    # This code allows this program to run equally well on my laptop and my desktop. I did it this
    # way to demonstrate different interface names. If I was really clever, I'd figure out how to do this
    # under MS-Windows
    #if sys.argv[1] == "-i" :
    #
    #elif sys.argv[1] == "-f" :
    #    pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    #else :
    print "inizio"
    pc = pcap.pcap()
    #print """Use -i INTERFACE to [packet capture from an interface.
        #Use -f FILENAME to read a packet capture file"""
        #sys.exipc = pcap.pcap()
    initialize_tables()

    pc.setfilter('port 53')
    print 'listening on %s: %s' % (pc.name, pc.filter)
    vettore_siti_errore=[]
    vettore_siti_ok=[]
    for (src, sport, dst, dport, data ) in udp_iterator(pc) :
        dns_core.processa(src,dst,sport,dport,data,vettore_siti_errore,vettore_siti_ok)


if __name__ == "__main__" :
    main()