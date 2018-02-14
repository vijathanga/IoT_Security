#!/usr/bin/python

from scapy.all import *
import threading
import socket
import time
import sys

import constant as ct
import libExtractor as ext

# GLOBAL VARIABLE
G_SOCK = None

class sniffer (threading.Thread):
    def __init__(self, evt_data):
      threading.Thread.__init__(self)

      # Filter for pcap
      self.evt_data = evt_data
      self.pcap = None

    def run(self):
        while True:
            # Sniff packets from interface until CAPTURE_TIMEOUT
            p = sniff(iface=ct.CAPTURE_IFACE, timeout=ct.CAPTURE_TIMEOUT, filter=ct.CAPTURE_FILTER)

            # Wait for main thread to send previous features to controller
            while self.evt_data.is_set():
                pass

            self.pcap = p
            self.evt_data.set()

def connectController():
    global G_SOCK

    # Try connecting to socket
    try:
        G_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ct.CONTROLLER_IP, ct.CONTROLLER_PORT)
        G_SOCK.connect(server_address)
        print "Connected to controller"
    except:
        G_SOCK = None

def sendData(pcap):
    global G_SOCK

    eArgs = ext.ExtractorArgs()
    eArgs.samplingTime = ct.SAMPLING_TIME
    eArgs.protocol = ct.PROTOCOL
    eArgs.pcap = pcap

    # Online feature extractor
    featureList = ext.extractAttributes(eArgs)

    # Format the obtained features
    msg = []
    for val in featureList:
        msg.append( ",".join(map(str, val)) )

    # Send features to the controller is controller connection has been made
    if msg:
        print "\n".join(map(str,msg))
        
        # Try contacting controller again
        if not G_SOCK:
            connectController()

        if G_SOCK:
            try:
                G_SOCK.sendall(";".join(map(str, msg)))
            except:
                print "\n\nProblem contacting server. Printing values locally"
                G_SOCK = None


def run():
    global G_SOCK

    # Event to synchronize with thread
    evt_data = threading.Event()

    # Try connecting to conntroller
    print 'Connecting to %s port %s' % (ct.CONTROLLER_IP, ct.CONTROLLER_PORT)

    connectController()

    if not G_SOCK:
        print "Unable to connect to server. Printing values locally."
    

    # Start the sniffer thread
    snoop = sniffer(evt_data)
    snoop.setDaemon(True)
    snoop.start()

    while True:
        evt_data.wait()                  # evt_data will be set when sniffer thread is ready with packet capture
        sendData(snoop.pcap)             # Process and send the captured packets to controller
        evt_data.clear()                 # Clear evt_data so that sniffer thread is unblocked
            
