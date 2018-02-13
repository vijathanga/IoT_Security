#!/usr/bin/python

import json
import argparse
import os

import extractor as ext
import predictor as prd

# GLOBAL CONSTANTS
KEY_CONF = "conf"

KEY_SAMPLING = "samplingTime"
KEY_PROTOCOL = "protocol"
KEY_META = "metadata"

KEY_FILE = "file"
KEY_LABEL = "label"
KEY_ATTACK_IP = "attackIP"
KEY_ATTACK_PROT = "attackProt"
KEY_PARSE = "parse"

CONF_FILE = "./res/conf.json"
FEATURE_FILE = "./res/features.csv"


def parseArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-e", "--extract", action="store_true", help="extract Features from pcap files")
    parser.add_argument("-n", "--no_prediction", action="store_true", help="turn off prediction")
    parser.add_argument("-d", "--delete", action="store_true", help="delete previous feature file")
    parser.add_argument("-c", "--conf", type=str, help="conf file location (default: ./conf.json)")
    parser.add_argument("-f", "--feature", type=str, help="feature file location (default: ./features.csv)")

    return parser.parse_args()

def parseJson(fileName):
    with open(fileName, 'r') as jsonFile:
        confJson = json.load(jsonFile)

    if KEY_CONF not in confJson:
        return False
    
    if KEY_SAMPLING not in confJson[KEY_CONF]:
        return False

    if KEY_PROTOCOL not in confJson[KEY_CONF]:
        return False

    if KEY_META not in confJson[KEY_CONF]:
        return False

    return confJson[KEY_CONF]

def extractFeatures(confFile):
    parse = ""

    confJson = parseJson(confFile)

    if confJson == False:
        print "Parsing of conf.json failed!"

    eArgs = ext.ExtractorArgs()

    eArgs.samplingTime = confJson[KEY_SAMPLING]
    eArgs.protocol = confJson[KEY_PROTOCOL]

    for meta in confJson[KEY_META]:
        eArgs.pcapFile = meta[KEY_FILE]
        parse = meta[KEY_PARSE]
        
        features = []

        if parse:
            print "Extracting features from \"" + eArgs.pcapFile + "\""

            eArgs.label = meta[KEY_LABEL]
            eArgs.attackIP = meta[KEY_ATTACK_IP]
            eArgs.attackProt = meta[KEY_ATTACK_PROT]

            features = ext.extractAttributes(eArgs)
            
            print "Extracted features - %d\n" % (len(features))

            # Write to file
            with open(FEATURE_FILE, 'a') as f:
                for feature in features:
                    f.write( ",".join(map(str,feature)) + '\n')
        else:
            print "Skipping " + eArgs.pcapFile + "\n"
            



if __name__ == '__main__':

    args = parseArguments()

    if args.conf:
        CONF_FILE = args.conf

    if args.feature:
        FEATURE_FILE = args.feature

    if args.delete:
        if os.path.isfile(FEATURE_FILE):
            os.remove(FEATURE_FILE)

    if args.extract:
        extractFeatures(CONF_FILE)

    if not args.no_prediction:
        pred = prd.Predictor(FEATURE_FILE)
        pred.train()
