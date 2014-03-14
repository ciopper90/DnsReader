import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core

def main() :

    if len(sys.argv) > 2:
        if sys.argv[1] == "-f" :
            pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
            dns_core.reader(pc)
        elif sys.argv[1] == "-i" :
            pc = pcap.pcap(name=sys.argv[2])
            predicato_di_filtro='port 53'
            pc.setfilter(predicato_di_filtro)
            print 'listening on %s: %s' % (pc.name, pc.filter)
            dns_core.reader(pc)
    else:
        print "usare -i ethX oppure -f file.pcap"

if __name__ == "__main__" :
    main()