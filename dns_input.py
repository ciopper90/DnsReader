import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core


port=53
dns_univ=['155.185.1.2','155.185.1.5']

sottorete_univ='155.185.0.0/16'


def main() :

    if len(sys.argv) > 2:
        if sys.argv[1] == "-f" :
            pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
        elif sys.argv[1] == "-i" :
            pc = pcap.pcap(name=sys.argv[2])
            print 'listening on %s: %s' % (pc.name, pc.filter)

        app=''
        for dns_selez in dns_univ:
            app=app+' not (src host '+ dns_selez + ' and not dst host '+ sottorete_univ+' ) and not (dst host '+ dns_selez + ' and not src host '+ sottorete_univ+' ) and '


        predicato_di_filtro='port '+ str(port)+' and '+app+' (host '+sottorete_univ+' )'
        print predicato_di_filtro
        pc.setfilter(predicato_di_filtro)
        dns_core.reader(pc)
    else:
        print "usare -i ethX oppure -f file.pcap"

if __name__ == "__main__" :
    main()