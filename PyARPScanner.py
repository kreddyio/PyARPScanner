#!/usr/bin/env python
import netifaces
import commands
import sys
from scapy.all import *


def scanner():
    # default = "route | grep 'default' | awk '{print $8}'"
    gws =  netifaces.gateways()
    default = gws['default'][netifaces.AF_INET]
    print 'Default Interface -- '+default[1]+' Gateway -- '+default[0]
    # diface = commands.getoutput(default)
    diface = default[1]
    srcip = netifaces.ifaddresses(diface)[2][0]['addr']
    netmask = netifaces.ifaddresses(diface)[2][0]['netmask']
    octets = srcip.split('.')
    starttime = time.time()
    global gw
    gw = octets[0] + "." + octets[1] + "." + octets[2]
    dest = gw + ".0/24"
    # print dest
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(dest)), timeout=2, verbose=0)
    endtime = time.time()
    ifaces = "ifconfig | grep -o " + str(diface) + " | wc -l"
    num = int(commands.getoutput(ifaces))
    setips = defaultdict(list)
    setips[diface].append(str(srcip))
    existing = [srcip]
    freeips = []
    totaltime = endtime - starttime
    print "Sent ARP requests in %f seconds..." % (totaltime)
    for i in range(0, num - 1):
        iface = diface + ":" + str(i)
        ip = netifaces.ifaddresses(iface)[2][0]['addr']
        setips[iface].append(str(ip))
        existing.append(str(ip))
    # print setips
    for i in range(0,len(answered)):
    	print "Response from ip -- " + answered[i][1].psrc + " using MAC -- " + answered[i][1].hwsrc
    print "Found %d ips that are already set to this computer." % (len(setips))
    for i in range(0, len(unanswered)):
        freeips.append(str(unanswered[i][1].pdst))
    freeips = set(freeips) - set(existing)
    freeips.remove(gw + '.0')
    freeips.remove(gw + '.255')
    # freeips.remove(gw+'.1')
    print "Found %d ips that are free." % (len(freeips))
    completedtime = time.time()
    totaltime = completedtime - starttime
    print "Completed scan in %f seconds..." % totaltime
    print 'The following ips are set to this computer',existing
    # unanswered = unanswered.remove(srcip)
    # return freeips
    # print setips

if __name__ == '__main__':
    scanner()