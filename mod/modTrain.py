#!/usr/bin/python

import json
import argparse
import os
import sys

import libExtractor as ext
import libPredictor as prd
import constant as ct


def extractFeatures():
    eArgs = ext.ExtractorArgs()

    eArgs.samplingTime = ct.SAMPLING_TIME
    eArgs.protocol = ct.PROTOCOL

    # Delete old feature file if APPEND_FEATURES is disabled
    if not ct.APPEND_FEATURES:
        if os.path.isfile(ct.FEATURE_FILE):
            print ("Deleting old feature file - " + ct.FEATURE_FILE)
            os.remove(ct.FEATURE_FILE)

    for pcap in ct.PCAPS:
        eArgs.pcapFile = pcap['file']
        parse = pcap['parse']
        
        features = []

        if parse:
            print ("Extracting features from \"" + eArgs.pcapFile + "\"")

            eArgs.label = pcap['label']
            eArgs.attackIP = pcap['attackIP']
            eArgs.attackProt = pcap['attackProt']

            # Extract features
            features = ext.extractAttributes(eArgs)
            
            print ("Extracted features - %d\n" % (len(features)))

            # Append to file
            with open(ct.FEATURE_FILE, 'a') as f:
                for feature in features:
                    f.write( ",".join(map(str, feature)) + '\n')
        else:
            print ("Skipping " + eArgs.pcapFile + "\n")
            
def run():

    # Extract features from pcap files
    if ct.EXTRACT_FEATURES:
        extractFeatures()

    # Train ML Classifiers
    if ct.PREDICTION:
        pred = prd.Predictor()
        pred.train()
