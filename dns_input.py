# -*- coding: utf-8 -*-
import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core
import time
import argparse




port=53
dns_univ=['155.185.1.2','155.185.1.5']

sottorete_univ='155.185.0.0/16'


def main() :




    ######################
    selettore=None
    devia_verso=None
    crea_risposta=0 #non crea risposta
    #crea_risposta=1 #crea risposta
    #crea_risposta=2 #risponde con no such domain




    ##########################


    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="da file")
    parser.add_argument("-i", help="da input")
    parser.add_argument("-p", help="risposta finta da porta")
    parser.add_argument("-q", help="risoluzione finta",nargs='?',default='0')

    ## se c'è p ma non c'è q dice NO SUCH DOMAIN
    ## in ho  -p <port> -q ->  porta su kitten war
    ## se no -p <port> -q <ip_reindirizzamento> porta su quell'ip la risoluzione

    parser.add_argument("-v","--verbosity", help="increase output verbosity")

    args = parser.parse_args()
    if args.verbosity:
        print "verbosity turned on"
    if args.f:
        selettore=1
        da_dove=args.f
    if args.i:
        selettore=2
        da_dove=args.i

    if args.p:
        crea_risposta=1
        da_porta=args.i

        if args.q=='0':
            ## non c'è il -q
            print "non c'è -q"
            crea_risposta=2
        else:
            if args.q:
                print "-q <",args.q,">"
                crea_risposta=1
                devia_verso=args.q
            else:
                a=1
                print "-q <vuoto>"
                crea_risposta=1
                devia_verso='64.64.4.109'#kitten war



    print args

    start_time = time.time()


    if selettore == 1 :
        pc = dpkt.pcap.Reader( open ( da_dove ) )
    elif selettore == 2 :
        pc = pcap.pcap(name=da_dove)
        print 'listening on %s: %s' % (pc.name, pc.filter)




    app=''
    for dns_selez in dns_univ:
        app=app+' not (src host '+ dns_selez + ' and not dst net '+ sottorete_univ+' ) and not (dst host '+ dns_selez + ' and not src net '+ sottorete_univ+' ) and '


    predicato_di_filtro='port '+ str(port)+' and '+app+' (net '+sottorete_univ+' )'
    print predicato_di_filtro
    pc.setfilter(predicato_di_filtro)
    dns_core.reader(pc,crea_risposta,devia_verso)
    ##se è dato un ip per dare come risoluzione questa è !=0
    print "Il tutto è stato eseguito in ",time.time() - start_time, "secondi"


if __name__ == "__main__" :
    main()