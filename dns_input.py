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
    parser.add_argument("-p", help="Interfaccia da cui inviare le risposte (default quella di -i)")
    parser.add_argument("-q", help="Risoluzione finta", default='no',nargs='?')
    parser.add_argument("-out", help="Nome dei file output, default 'output_xxxxx'",default='output')

    ## se c'è p ma non c'è q dice NO SUCH DOMAIN
    ## se devi essere coerente con quello che hai detto stamattina, anche se c'è -p <interfaccia> -q (senza altro)
    ## manda no such domain quindi scelta ==2 , oppure hai cambiato idea?
    ## se no -p <port> -q <ip_reindirizzamento> dirige verso quell'ip la risoluzione dns richiesta (spoof+tarocco )

    ## la risposta è creata  se mette -p <int> [ -q [ip] ]


    args = parser.parse_args()


    if args.f and args.i:
        print " -f e -i sono ad uso: UNO ESCLUDE L'ALTRO"
        exit (2)

    if args.f:
        selettore=1
        print "apre da file"
        da_dove=args.f
        if args.p  :
            print " con -f non è ammesso -p !"
            exit (3)
        if args.q != 'no':
            print " con -f non è ammesso -q [opz] !"
            exit (4)

    if args.i:
        selettore=2
        da_dove=args.i
        #print " apre da interfaccia"

        #porta di risposta ( interfaccia)
        if args.p:
            da_porta=args.p
            #print " vuole inviare risposte false"
        else:
            da_porta=da_dove
            #print " NON vuole inviare risposte false"

        if args.q != 'no':
           if args.q:
                #print "-q <",args.q,">"  #devio verso
                crea_risposta=1
                devia_verso=args.q
           else:
              # print "-q , rispondo con nxd" # rispondo no such domain
               crea_risposta=2
        else:
            #print "non c'è la -q , rispondo nxd" # ma sempre no such domain rispondo!
            crea_risposta=2


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
    #print predicato_di_filtro
    pc.setfilter(predicato_di_filtro)
    dns_core.reader(pc,args.out,crea_risposta,devia_verso,da_porta)
    ##crea_risposta == 0 non crea niente
    ## == 1 Crea Risposta
    ## == 2 NOSUCHDOMAIN

    print "Il tutto è stato eseguito in ",time.time() - start_time, "secondi"


if __name__ == "__main__" :
    main()