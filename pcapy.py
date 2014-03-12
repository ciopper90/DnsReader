import dpkt
import socket

#filename = raw_input('vodafone')
path = '/home/ciopper90/PycharmProjects/Pcap/test1.pcap'# + filename + ''
f = open(path, 'rb')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
    #make sure we are dealing with IP traffic
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except:
        continue
    if eth.type != 2048:
        continue
    #make sure we are dealing with UDP protocol
    try:
        ip = eth.data
    except:
        continue
    if ip.p != 17:
        continue
    #filter on UDP assigned ports for DNS
    try:
        udp = ip.data
    except:
        continue
    if udp.sport != 53 and udp.dport != 53:
        continue
    #make the dns object out of the udp data and
    #check for it being a RR (answer) and for opcode QUERY
    try:
        dns = dpkt.dns.DNS(udp.data)
    except:
        continue

    for qname in dns.qd:
        if len(dns.an) == 0:
            print qname.name ,qname.data
    #if dns.qr != dpkt.dns.DNS_R:
    #    continue
    #if dns.opcode != dpkt.dns.DNS_QUERY:
    #    continue
    #if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
    #    continue
    #if len(dns.an) < 1:
    #    continue

    #process and print responses based on record type
    #for answer in dns.an:
    #    if answer.type == 1: #DNS_A
    #        print 'Domain Name: ', answer.name, '\tIP Address: ', socket.inet_ntoa(answer.rdata)
