#!/usr/bin/python
#
"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2012-2015 George Kargiotakis


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import sys, os
import re
import syslog
import time
import netaddr
import IPy
import radix
from ConfigParser import ConfigParser
import ast
from IPy import IP

syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)
syslog.syslog('PipeBackend starting up')

### DEBUG ###
debug=0

#non-round subnet hack
# nrdelegation = 1
# splitting a /40 to /56 delegations
# 2001:db8:1000::/40 -> 2001:db8:1000:0000::/56
#                       2001:db8:1000:0100::/56
#                       2001:db8:1000:0200::/56
#                       ....
#                       2001:db8:1001:0000::/56
#                       ....
#                       2001:db8:10ff:ff00::/56
# How to use:
# Nibbles: 0    1    2    3
#         2001:db8:1000:1234::
# So the default settings of:
# startnibble=2
# provide:      2001:db8:10|XX:XX|00::
# startnibble=1
# provide:      2001:80|XX:XX|00:0000::
nrdelegation=0
startnibble=2


class HierDict(dict):
    def __init__(self, parent=None, default=None):
        self._parent = parent
        if default != None:
            self.update(default)

    def __getitem__(self, name):
        try:
            return super(HierDict,self).__getitem__(name)
        except KeyError, e:
            if self._parent is None:
                raise
            return self._parent[name]

DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'

rtree=radix.Radix()

mypars=ConfigParser()
mypars.read('/etc/powerdns/configs/defaults.config')
for section_name in mypars.sections():
    options=mypars.get(section_name,'dict')
    dic=ast.literal_eval(options)
    globals()[section_name]=dic.copy()

parser = ConfigParser()
parser.read('/etc/powerdns/configs/prefixes.config')

PREFIXES={}
for section_name in parser.sections():
    defaults=parser.get(section_name,'defaults')
    options=parser.get(section_name,'options')
    dic=ast.literal_eval(options)
    PREFIXES[netaddr.IPNetwork(section_name)]=HierDict(eval(defaults),dic)
    #testing
    node2=rtree.add(str(section_name))
    node2.data['defaults']=defaults
    node2.data['options']=options

for prefix in PREFIXES.keys():
    node=rtree.add(str(prefix))
    node.data['prefix']=prefix

def base36encode(n):
    s = ''
    while True:
        n, r = divmod(n, len(DIGITS))
        s = DIGITS[r] + s
        if n == 0:
            break
    return s

def base36decode(s):
    n, s = 0, s[::-1]
    for i in xrange(0, len(s)):
        r = DIGITS.index(s[i])
        n += r * (len(DIGITS) ** i)
    return n

# Search whether a reverse query belongs to a node in prefixes
def revsearch_qname(qname):
    qname=qname.lower()
    nibbles = qname.split('.')
    nibbles.pop() #drop 'arpa'
    nibbles.pop() #drop 'in-addr' or 'ip6'
    nibbles.reverse()
    if (len(nibbles) == 3):      # qname like X.Y.Z.in-addr.arpa
        mystring = '.'.join(nibbles)
        finalstring = mystring + str('.0')
    elif (len(nibbles) == 2):    # qname like Y.Z.in-addr.arpa
        mystring = '.'.join(nibbles)
        finalstring = mystring + str('.0.0')
    elif (len(nibbles) == 1):    # qname like Z.in-addr.arpa
        mystring = '.'.join(nibbles)
        finalstring = mystring + str('.0.0.0')
    elif (len(nibbles) == 4):    # qname like W.X.Y.Z.in-addr.arpa
        finalstring = '.'.join(nibbles)
    elif (len(nibbles) == 0):    # qname like in-addr.arpa
        return None
    elif (len(nibbles) > 4 and len(nibbles) < 32): #TODO
        return None
    elif (len(nibbles) == 32):  #IPv6
        count=0
        finalstring=''
        for nibble in nibbles:
            if (count % 4 == 0 and count >0): #reconstruct IPv6 address from reverse
                finalstring = finalstring + ":" + nibble
            else:
                finalstring = finalstring + nibble
            count += 1
    #search radix tree for existence of
    node = rtree.search_best(finalstring)
    if node:
        return node
    else:
        return None


def parse(fd, out):
    line = fd.readline().strip()
    if not line.startswith('HELO'):
        print >>out, 'FAIL'
        out.flush()
        syslog.syslog('received "%s", expected "HELO"' % (line,))
        sys.exit(1)
    else:
        print >>out, 'OK\t%s ready with %d prefixes configured' % (os.path.basename(sys.argv[0]),len(PREFIXES))
        out.flush()
        syslog.syslog('received HELO from PowerDNS')

    lastnet=0
    while True:
        line = fd.readline().strip()
        if not line:
            break
        if debug:
            syslog.syslog('LINE: "%s"' % (line,))

        request = line.split('\t')
        if debug:
            syslog.syslog('REQUEST: "%s"' % (request,))
        if request[0] == 'AXFR':
                if not lastnet == 0:
                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 1209600 3600' % \
                                (lastnet['forward'], 'IN', lastnet['ttl'], qid, lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H'))
                        lastnet=lastnet
                        for ns in lastnet['nameserver']:
                                print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                                        (lastnet['forward'], 'IN', lastnet['ttl'], qid, ns)
                print >>out, 'END'
                out.flush()
                continue
        if len(request) < 6:
            print >>out, 'LOG\tPowerDNS sent unparsable line'
            print >>out, 'FAIL'
            out.flush()
            continue


        try:
                kind, qname, qclass, qtype, qid, ip = request
        except:
                kind, qname, qclass, qtype, qid, ip, their_ip = request
        #debug
#       print >>out, 'LOG\tPowerDNS sent qname>>%s<< qtype>>%s<< qclass>>%s<< qid>>%s<< ip>>%s<<' % (qname, qtype, qclass, qid, ip)
        qname=qname.lower()
        if qtype in ['AAAA', 'ANY']:
            if debug:
                syslog.syslog('*** AAAA or ANY ** %s ### %s' %  (qname,qtype,))
                #print >>out, 'LOG\twe got a AAAA query'
            for range, key in PREFIXES.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    if (key['showclientid'] == 1):
                        deccustomerid=int(node.split('-')[0])
                        hexcustomerid=hex(deccustomerid)[2:]
                        node = node.split('-')[1]
                        mynetwork = str(range).split('/')[0]
                        mynetwork = mynetwork.split(':')[:-2]
                        mynetwork.append(hexcustomerid)
                        newrange = ':'.join(mynetwork) + '::'
                        newrange = netaddr.IPNetwork(newrange)
                        newrange = newrange.ip
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if debug:
                        syslog.syslog('***** %s ### %s @@@ %s *** %s ### %s #### %s' % \
                                    (qname,node,deccustomerid,hexcustomerid,mynetwork,newrange))
                    if node:
                        if (key['showclientid'] == 1):
                            ipv6 = netaddr.IPAddress(long(newrange.value) + long(node))
                        else:
                            ipv6 = netaddr.IPAddress(long(range.value) + long(node))
                        print >>out, 'DATA\t%s\t%s\tAAAA\t%d\t%s\t%s' % \
                            (qname, qclass, key['ttl'], qid, ipv6)
                    break
        if qtype in ['A', 'ANY']:
            if debug:
                syslog.syslog('*** A or ANY ** %s ### %s' %  (qname,qtype,))
                #print >>out, 'LOG\twe got a A query'
            for range, key in PREFIXES.iteritems():
                if debug:
                    syslog.syslog('DEBUG range=%s qname=%s keyf=%s keyp=%s' % (range,qname,key['forward'],key['prefix'],))
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
                    if debug:
                        syslog.syslog('DEBUG *** found match, replying')
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        #ipv4 = netaddr.IPAddress(long(range.value) + long(node))
                        ipv4 = netaddr.IPAddress(long(node))
                        print >>out, 'DATA\t%s\t%s\tA\t%d\t%s\t%s' % \
                            (qname, qclass, key['ttl'], qid, ipv4)
                    break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            if debug:
                syslog.syslog('*** PTR or ANY ** %s ### %s' %  (qname,qtype,))
                #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            #ALTERNATE NAMING
            ipv6addr = ipv6
            try:
                ipv6 = netaddr.IPAddress(ipv6)
            except:
                ipv6 = netaddr.IPAddress('::')
            node=rtree.search_best(str(ipv6))
            if node:
                range, key = node.data['prefix'], PREFIXES[node.data['prefix']]
                #ALTERNATE NAMING
                if (key['showclientid'] == 1):
                    #hack for /40 delegation (blame aduitsis!)
                    if (key['nrdelegation'] == 1):
                        hexcustomerid1=ipv6addr.split(':')[startnibble][2:]
                        hexcustomerid2=ipv6addr.split(':')[startnibble + 1][:-2]
                        hexcustomerid = hexcustomerid1 + hexcustomerid2
                    else:
                        hexcustomerid=ipv6addr.split(':')[3]
                    deccustomerid = int(hexcustomerid, 16)
                    mynetwork = str(range).split('/')[0]
                    mynetwork = mynetwork.split(':')[:-2]
                    mynetwork.append(hexcustomerid)
                    myprefix = int(str(range).split('/')[1])
                    myprefix += 16
                    newrange = ':'.join(mynetwork) + '::/' + str(myprefix)
                    newrange = netaddr.IPNetwork(newrange)
                    newrange = newrange.ip
                    node = ipv6.value - newrange.value
                else:
                    node = ipv6.value - range.value
                node = base36encode(node)
                #ALTERNATE NAMING
                if (key['showclientid'] == 1):
                    node = str(deccustomerid) + '-' + node
                print >>out, 'DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s' % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])

        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            if debug:
                syslog.syslog('** PTR4 ** %s ### %s' %  (qname,qtype,))
                #print >>out, 'LOG\twe got a PTR query'
            ptr = qname.split('.')[:-2][::-1]
            ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            node=rtree.search_best(str(ipv4))
            if node:
                range, key = node.data['prefix'], PREFIXES[node.data['prefix']]
                #node = ipv4.value - range.value
                node = ipv4.value
                node = base36encode(node)
                print >>out, 'DATA\t%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s' % \
                    (qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])


        if qtype in ['SOA', 'ANY', 'NS']:
                qname=qname.lower()
                if debug:
                    syslog.syslog('*** SOA or NS or ANY ** %s ### %s' %  (qname,qtype,))
                if (qname.endswith('.arpa')):
                        #testing section
                        mynode=None
                        mynode=revsearch_qname(qname)
                        try:
                            defname=mynode.data['defaults']
                            ropt=ast.literal_eval(mynode.data['options'])
                            defopt = globals()[defname].copy()
                            if (qname.endswith('.arpa') and mynode != None):
                                    if debug:
                                        syslog.syslog('# REVERSE #')
                                    if not qtype == 'NS':
                                            print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 1209600 3600' % \
                                                   (qname, qclass, defopt['ttl'], qid,defopt['dns'], defopt['email'], time.strftime('%Y%m%d%H'))
                                            lastnet=ropt
                                            lastnet.update(defopt)
                                    if qtype in ['ANY', 'NS']:
                                            for ns in defopt['nameserver']:
#                                                print >>out, 'LOG\t%s\t%s\tNS\t%d\t%s\t%s' % \
#                                                        (qname, qclass, key['ttl'], qid, ns)
                                                 print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                                                         (qname, qclass, defopt['ttl'], qid, ns)
#                                break
                        except AttributeError:
                            pass
                else:
                    for range, key in PREFIXES.iteritems():
                        if qname == key['forward']:
                                if debug:
                                    syslog.syslog('# FORWARD #')
                                if not qtype == 'NS':
                                        if debug:
                                            syslog.syslog('# !NS #')
                                        print >>out, 'DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 1209600 3600' % \
                                                (key['forward'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H'))
                                        lastnet=key
                                if qtype in ['ANY', 'NS']:
                                        if debug:
                                            syslog.syslog('# ANY or NS #')
                                        for ns in key['nameserver']:
                                                print >>out, 'DATA\t%s\t%s\tNS\t%d\t%s\t%s' % \
                                                        (key['forward'], qclass, key['ttl'], qid, ns)
                                break

        print >>out, 'END'
        out.flush()

    syslog.syslog('terminating')
    return 0

for zone in PREFIXES:
    if not PREFIXES[zone].has_key('domain'):
        from IPy import IP
        PREFIXES[zone]['domain']=IP(str(zone.cidr)).reverseName()[:-1]

if __name__ == '__main__':
    import sys
    sys.exit(parse(sys.stdin, sys.stdout))
