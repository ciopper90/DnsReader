# -*- coding: utf-8 -*-
import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core
import time



port=53
dns_univ=['155.185.1.2','155.185.1.5']

sottorete_univ='155.185.0.0/16'


def main() :
    start_time = time.time()

    if len(sys.argv) > 2:
        if sys.argv[1] == "-f" :
            pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
        elif sys.argv[1] == "-i" :
            pc = pcap.pcap(name=sys.argv[2])
            print 'listening on %s: %s' % (pc.name, pc.filter)

        devia_verso=''
        crea_risposta=0 #non crea risposta
        #crea_risposta=1 #crea risposta
        #crea_risposta=2 #risponde con no such domain

        app=''
        for dns_selez in dns_univ:
            app=app+' not (src host '+ dns_selez + ' and not dst net '+ sottorete_univ+' ) and not (dst host '+ dns_selez + ' and not src net '+ sottorete_univ+' ) and '


        predicato_di_filtro='port '+ str(port)+' and '+app+' (net '+sottorete_univ+' )'
        print predicato_di_filtro
        pc.setfilter(predicato_di_filtro)
        dns_core.reader(pc,crea_risposta,devia_verso)
        ##se è dato un ip per dare come risoluzione questa è !=0
        print "Il tutto è stato eseguito in ",time.time() - start_time, "secondi"
    else:
        print "usare -i ethX oppure -f file.pcap"

if __name__ == "__main__" :
    main()