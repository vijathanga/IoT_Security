#!/usr/bin/python

import sys
import socket
import os

import constant as ct
import libFlowPusher as pusher
from sklearn.externals import joblib

G_SOCK = None
CONNECTION = None

def loadClassifier():
    clf = None

    try:
        filePath = os.path.join(ct.CLASSIFIER_PATH, ct.CLASSIFIER)
        clf = joblib.load(filePath)
        print "Loaded " + filePath
    except:
        print "Failed to load classifier"

    return clf
    


def listenSwitch():
    global G_SOCK, CONNECTION

    # Listen for incoming connections
    G_SOCK.listen(1)
    print 'Waiting for a connection...'

    CONNECTION, switchIP = G_SOCK.accept()
    print 'Connection from', switchIP



def run():
    global G_SOCK, CONNECTION
    blockedIP = []

    # Initialize flow pusher
    pusher.initialize()

    # Load Classifier
    clf = loadClassifier() 

    # Bind to a socket
    G_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', ct.CONTROLLER_PORT)

    print 'Starting server on localhost port %s' % server_address[1]
    G_SOCK.bind(server_address)

    # Listen for incoming connections
    listenSwitch()

    try:
        while True:
            data = CONNECTION.recv(1000)

            # If data is received, extract individual flow features 
            if data:
                flows = data.split(";")

                # Extract individual flow features
                for flow in flows:
                    val = flow.split(",")
                    srcIP = val[0]
                    dstIP = val[1]

                    # Slice only only feature values (Exclude src and dst IP address)
                    X = list(map(float, val[2:]))
                    
                    if clf:
                        atkCls = clf.predict([X])[0]
                        print "%-*s - %-*s -> %s" % (15, srcIP, 15, dstIP, ct.LABELS[atkCls])

                        if atkCls != 0:
                            if srcIP not in blockedIP:
                                pusher.blockHost('block_' + srcIP, srcIP )
                                blockedIP.append(srcIP)

                    else:
                        print "%-*s - %-*s  %s" % (15, val[0], 15, val[1], ','.join(map(str,X)))

            else:
                print "Disconnnected from switch"
                listenSwitch()
                		
    finally:
        # Clean up the connection
        CONNECTION.close()
