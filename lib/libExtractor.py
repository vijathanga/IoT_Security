#!/usr/bin/python

from scapy.all import *
import numpy as np

class ExtractorArgs:
    def __init__(self):
        self.pcapFile = None
        self.pcap = None
        self.deviceIP = None
        self.protocol = []
        self.samplingTime = 0
        self.attackIP = None
        self.attackProtocol = None
        self.label = None

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

    def __init__(self, pkt, initFeatures):
        self.featureList = initFeatures

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

    def extractPacket(self, pkt):

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
        self.interArrivalTime()

        self.featureList.append (self.__prot.index(self.prot))

        # TCP attributes
        self.featureList.extend(self.TcpFlag)
        #featureList.append(self.tcpPorts())

        # ICMP attributes
        self.featureList.extend(self.IcmpCode)

        # Flow statistics
        self.featureList.extend([self.meanInterArrTime(),
                                 self.varInterArrTime(),
                                 self.minInterArrTime(),
                                 self.maxInterArrTime(),
                                 self.meanPktLen(),
                                 self.varPktLen(),
                                 self.minBytes(),
                                 self.maxBytes(),
                                 self.totalPkts(),
                                 self.totalBytes()])

        return self.featureList

    def matchAndAddPacket(self, pkt):

        if pkt.haslayer(self.prot):
            if (self.src == pkt['IP'].src and self.dst == pkt['IP'].dst):
                self.__time.append(pkt.time)
                self.__pktLen.append(len(pkt))

                self.extractPacket(pkt)
                # self.rawPackets.append(pkt)

                return True

        return False

class Extractor:

    def __init__(self, eArgs):
        self.featureList = []
        self.flows = []
        self.sessTime = None
        self.online = eArgs.pcap != None

        self.pcapFile = eArgs.pcapFile
        self.pcap = eArgs.pcap
        self.samplingTime = eArgs.samplingTime
        self.label = eArgs.label

        self.includeFilter = Filter()
        self.includeFilter.prot = eArgs.protocol
        self.includeFilter.devIP = eArgs.deviceIP

        self.labelFilter = Filter()
        self.labelFilter.srcIP = eArgs.attackIP
        self.labelFilter.prot = eArgs.attackProtocol

    def extractPacket(self, packet):

        # Sampling is only for offline extraction
        if not self.online:
            # First packet in pcap file
            if self.sessTime == None:
                self.sessTime = packet.time + self.samplingTime

            # Initialize for next sampling period
            if (packet.time > self.sessTime):
                for f in self.flows:
                    self.featureList.append(f.getAttr())

                # Reset flows
                self.flows = []
                self.sessTime = self.sessTime + self.samplingTime

        # Process packets which are matched by input filter
        if self.includeFilter.match(packet):

            # Look for a flow to which the packet belongs
            matched = False
            for f in self.flows:
                if f.matchAndAddPacket(packet):
                    matched = True
                    break

            # If no flows are found, create a new flow
            if not matched:
                # Initial features vary for online and offline flows
                if self.online:
                    initFeatures = [packet['IP'].src, packet['IP'].dst]
                else:
                    initFeatures = [self.label if self.labelFilter.match(packet) else 0]

                # Add new flow to the flow list
                newFlow = Flow(packet, initFeatures)
                self.flows.append(newFlow)

    def extractFeatures(self):
        self.featureList = []
        self.flows = []
        self.sessTime = None

        if self.online:
            # Real time feature extraction
            for packet in self.pcap:
                self.extractPacket(packet)
        else:
            # Feature extraction from pcap
            with PcapReader(self.pcapFile) as pcap:
                for packet in pcap:
                    self.extractPacket(packet)

        # Append all features
        for f in self.flows:
            self.featureList.append(f.getAttr())


def extractAttributes(extractorArgs):

    ft = Extractor(extractorArgs)
    ft.extractFeatures()

    return ft.featureList



if __name__ == "__main__":

    #pcap_file = 'pcap/TCP/TCP_Dlink_camera.pcap'
    p = sniff(iface='ens33', timeout=10, count=50)

    eArgs = ExtractorArgs()
    #eArgs.samplingTime = 1
    #eArgs.attackIP = "192.168.1.1"
    #eArgs.pcapFile = 'pcap/test/test.pcap'
    eArgs.protocol = ['TCP']
    eArgs.pcap = p
    #eArgs.label = 1

    ft = extractAttributes(eArgs)

    for feature in ft:
        print (",".join(map(str,feature)))
