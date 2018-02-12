#!/usr/bin/python

from scapy.all import *
import numpy as np


ATTR = ["label", "prot", "syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr", "echoReq", "echoRply",
                 "meanArrTime", "varArrTime", "minArrTime", "maxArrTime", 
                 "meanPktLen",  "varPktLen",  "minBytes",   "maxBytes",   "totPkt", "totBytes"]

KALI_IP = ''
L_VALUE = 0



class Filter:
    def __init__(self):
        self.prot = None
        self.devIP = None
        self.srcIP = None
        self.dstIP = None
        self.srcPort = None
        self.dstPort = None

    def match(self, pkt):
        if (self.prot != None):

            bProt = False
            for protocol in self.prot:
                if pkt.haslayer(protocol):
                    bProt = True

            if not bProt: return False

        if (self.devIP != None or self.srcIP != None or self.dstIP != None):
            if (not pkt.haslayer("IP")):
                return False

            if (self.devIP != None):
                if (pkt["IP"].src != self.devIP  and  pkt["IP"].dst != self.devIP):
                    return False

            if (self.srcIP != None and pkt["IP"].src != self.srcIP):
                return False

            if (self.dstIP != None and pkt["IP"].dst != self.srcIP):
                return False

        
        return True

class Flow:
    FIN = 0x01; SYN = 0x02; RST = 0x04; PSH = 0x08; ACK = 0x10; URG = 0x20; ECE = 0x40; CWR = 0x80
    syn = 0; fin = 1; rst = 2; psh = 3; ack = 4; urg = 5; ece = 6; cwr = 7 

    echoReq = 0; echoRply = 1

    __prot = [ 'nil', 'ICMP', 'ARP', 'UDP', 'SDP', 'EFK', 'TCP' ]

    def __init__(self, pkt):
        self.src = pkt['IP'].src
        self.dst = pkt['IP'].dst

        self.prot = self.__prot[ pkt['IP'].proto ]

        # TCP attirbutes
        self.TcpFlag = [0] * 8  
        self.ports = []

        # ICMP attributes
        self.IcmpCode = [0] * 2

        self.__time = []                # Arrival times of pkts in current session
        self.__pktLen = []              # Len of pkts in current session
        self.__interArrivalTime = []
        self.rawPackets = []

        self.matchAndAddPacket(pkt)

    def tcpPorts(self):
        return len(self.ports)

    def interArrivalTime(self):

        if len(self.__time) <= 1:
            self.__interArrivalTime.append(0)
            return

        self.__time.sort()
        
        for i in range(1, len(self.__time)):
            interval = self.__time[i] - self.__time[i-1]
            self.__interArrivalTime.append( abs(interval) )

    def meanInterArrTime(self):
        return np.mean(self.__interArrivalTime)

    def varInterArrTime(self):
        return np.var(self.__interArrivalTime)

    def minInterArrTime(self):
        return min(self.__interArrivalTime)

    def maxInterArrTime(self):
        return max(self.__interArrivalTime)

    def meanPktLen(self):
        pktLenSum = 0.0

        if len(self.__pktLen) == 0:
            return 0

        return np.mean(self.__pktLen)

    def varPktLen(self):
        return np.var(self.__pktLen)

    def minBytes(self):
        return min(self.__pktLen)
    
    def maxBytes(self):
        return max(self.__pktLen)

    def totalPkts(self):
        return len(self.__pktLen)

    def totalBytes(self):
        return sum(self.__pktLen)

    def extractAttr(self, pkt):

        if self.prot == 'TCP':
            flag = pkt['TCP'].flags

            if (flag & self.SYN and not flag & self.ACK):
                self.TcpFlag[self.syn] = self.TcpFlag[self.syn] + 1
            if (flag & self.FIN):
                self.TcpFlag[self.fin] = self.TcpFlag[self.fin] + 1
            if (flag & self.RST):
                self.TcpFlag[self.rst] = self.TcpFlag[self.rst] + 1
            if (flag & self.PSH):
                self.TcpFlag[self.psh] = self.TcpFlag[self.psh] + 1
            if (flag & self.ACK):
                self.TcpFlag[self.ack] = self.TcpFlag[self.ack] + 1
            if (flag & self.URG):
                self.TcpFlag[self.urg] = self.TcpFlag[self.urg] + 1
            if (flag & self.ECE):
                self.TcpFlag[self.ece] = self.TcpFlag[self.ece] + 1
            if (flag & self.CWR):
                self.TcpFlag[self.cwr] = self.TcpFlag[self.cwr] + 1

            port = pkt['TCP'].dport
            if port not in self.ports:
                self.ports.append(port)



        elif self.prot == 'ICMP':
            if pkt['ICMP'].type == 8:
                self.IcmpCode[self.echoReq] = self.IcmpCode[self.echoReq] + 1

            if pkt['ICMP'].type == 0:
                self.IcmpCode[self.echoRply] = self.IcmpCode[self.echoRply] + 1

    def getAttr(self):
        global KALI_IP, L_VALUE
        self.interArrivalTime()

        label = L_VALUE if int( (self.src == KALI_IP) ) else 0

        featureList = [ label, self.__prot.index(self.prot) ]

        # TCP attributes
        featureList.extend(self.TcpFlag)
        #featureList.append(self.tcpPorts())

        # ICMP attributes
        featureList.extend(self.IcmpCode)

        # Flow statistics
        featureList.extend([self.meanInterArrTime(),
                            self.varInterArrTime(),
                            self.minInterArrTime(),
                            self.maxInterArrTime(),
                            self.meanPktLen(),
                            self.varPktLen(),
                            self.minBytes(),
                            self.maxBytes(),
                            self.totalPkts(),
                            self.totalBytes()])

        return featureList

    def matchAndAddPacket(self, pkt):

        if pkt.haslayer(self.prot):
            if (self.src == pkt['IP'].src and self.dst == pkt['IP'].dst):
                self.__time.append(pkt.time)
                self.__pktLen.append(len(pkt))

                self.extractAttr(pkt)
                # self.rawPackets.append(pkt)

                return True

        return False

class Extractor:

    def __init__(self, pcapFile, ip, controllerIP, protocol, sampling = 0):
        self.flows = []
        self.featureList = []
        self.pcapFile = pcapFile

        self.includeFilter = Filter()
        self.includeFilter.prot = protocol
        self.includeFilter.devIP = ip
        
        self.excludeFilter = Filter()
        self.excludeFilter.devIP = controllerIP

        # Used for offline extraction (Time in seconds)
        self.samplingTime = sampling

    def extractFeatures(self):
        self.flows = []
        self.featureList = []
        sessTime = None


        with PcapReader(self.pcapFile) as pcap:
            for packet in pcap:
                if sessTime == None:
                    sessTime = packet.time + self.samplingTime

                if (self.samplingTime != 0) and (packet.time > sessTime):
                    for f in self.flows:
                        self.featureList.append(f.getAttr())

                    self.flows = []
                    sessTime = sessTime + self.samplingTime

                # Exclude Filter for controller IP
                if (self.samplingTime == 0) and self.excludeFilter.match(packet):
                    continue

                if self.includeFilter.match(packet):

                    matched = False
                    for f in self.flows:
                        if f.matchAndAddPacket(packet):
                            matched = True
                            break

                    if not matched:
                        newFlow = Flow(packet)
                        self.flows.append(newFlow)

        if not self.featureList:
            for f in self.flows:
                self.featureList.append(f.getAttr())


def extractOffline(pcapFile, samplingTime, prot, kaliIp, labelValue):
    global KALI_IP, L_VALUE

    KALI_IP = kaliIp
    L_VALUE = labelValue

    ft = Extractor(pcapFile, None, None, prot, samplingTime)
    ft.extractFeatures()

    return ft.featureList



if __name__ == "__main__":

    samplingTime = 1.0     # Sampling time

    #pcap_file = 'pcap/TCP/TCP_Dlink_camera.pcap'
    pcap_file = 'pcap/PScan/PScan_Dlink_camera.pcap'

    pcap = rdpcap(pcap_file)
    #p = sniff(iface='ens33', timeout=5, count=50)

    protocol = ['TCP']
    ft = Extractor(None, None, protocol, samplingTime)
    ft.extractFeatures()

    for feature in ft.featureList:
        print ",".join(map(str,feature))
