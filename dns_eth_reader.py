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
    pc = pcap.pcap('eth0')
    #print """Use -i INTERFACE to [packet capture from an interface.
        #Use -f FILENAME to read a packet capture file"""
        #sys.exipc = pcap.pcap()
    initialize_tables()

    predicato_di_filtro='port 53'
    pc.setfilter(predicato_di_filtro)
    print 'listening on %s: %s' % (pc.name, pc.filter)
    vettore_siti_errore=[]
    vettore_siti_ok=[]
    apri_output('output_da_risposta_nxdomain','output_da_richiesta_dns_nowl')
    for (src, sport, dst, dport, data ) in udp_iterator(pc) :
        dns_core.processa(src,dst,sport,dport,data,vettore_siti_errore,vettore_siti_ok,output_da_risposta_nxdomain,output_da_richiesta_dns_nowl)


    chiudi_file()


if __name__ == "__main__" :
    main()