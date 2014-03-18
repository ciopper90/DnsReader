# -*- coding: utf-8 -*-
import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import dns_core
import time
import argparse
import csv




port=53

dns_univ=[]

sottorete_univ='155.185.0.0/16'


def main() :




    ######################
    selettore=None
    devia_verso=None
    crea_risposta=0 #non crea risposta
    #crea_risposta=1 #crea risposta
    #crea_risposta=2 #risponde con no such domain
    da_porta=None




    ##########################


    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="Da file")
    parser.add_argument("-i", help="Da input")
    parser.add_argument("-p", help="porta da cui inviare la risposta(default quella di -i)")
    parser.add_argument("-q", help="Risoluzione finta", default='no',nargs='?')
    parser.add_argument("-out", help="Nome dei file output, default 'output_xxxxx'",default='output')

    ## se c'è p ma non c'è q dice NO SUCH DOMAIN
    ## se no -p <port> -q <ip_reindirizzamento> porta su quell'ip la risoluzione

    parser.add_argument("-v","--verbosity", help="increase output verbosity")

    args = parser.parse_args()
    if args.verbosity:
        print "verbosity turned on"

    if args.f and args.i:
        print " -f e -i sono ad uso: UNO ESCLUDE L'ALTRO"
        exit (2)

    if args.f:
        selettore=1
        da_dove=args.f
        if args.p and args.q != 'no':
            print " con -f non sono ammessi altri -p / -q vari !"
            exit (3)

    if args.i:
        selettore=2
        da_dove=args.i

        #porta di risposta
        if args.p:
            da_porta=args.p
        else:
            da_porta=da_dove

        if args.q != 'no':
           if args.q:
                print "-q <",args.q,">"
                crea_risposta=1
                devia_verso=args.q
           else:
                crea_risposta=2
        else:
            crea_risposta=0


    #print args

    start_time = time.time()


    if selettore == 1 :
        pc = dpkt.pcap.Reader( open ( da_dove ) )
    elif selettore == 2 :
        pc = pcap.pcap(name=da_dove)
        print 'listening on %s: %s' % (pc.name, pc.filter)


    with open('dns_whitelist.csv', 'rb') as csvfile:
        reader=csv.reader(csvfile, delimiter=',', quotechar='|')
        for i in reader:
             dns_univ.append(i[0])

    app=''
    for dns_selez in dns_univ:
        app=app+' and not (src host '+ dns_selez + ' and not dst net '+ sottorete_univ+' ) and not (dst host '+ dns_selez + ' and not src net '+ sottorete_univ+' ) '


    predicato_di_filtro='port '+ str(port)+app#+' (net '+sottorete_univ+' )'
    print predicato_di_filtro
    pc.setfilter(predicato_di_filtro)
    dns_core.reader(pc,args.out,crea_risposta,devia_verso,da_porta)
    ##crea_risposta == 0 non crea niente
    ## == 1 Crea Risposta
    ## == 2 NOSUCHDOMAIN

    print "Il tutto è stato eseguito in ",time.time() - start_time, "secondi"


if __name__ == "__main__" :
    main()