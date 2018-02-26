#!/usr/bin/python

from scapy.all import *
import argparse


def parseArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--pcap", type=str, help="pcap file to analyse")
    parser.add_argument("-i", "--ip", type=str, help="IP to check for first and last occurence")

    return parser.parse_args()


if __name__ == '__main__':
    args = parseArguments()

    #args.ip = "192.168.137.179"
    #args.pcap = "./res/pcap/bandwidth/TCP_2s_5.pcap"

    pcap = rdpcap(args.pcap)
    flow = []

    ST = 0.5
    start = pcap[0].time

    time = pcap[0].time + ST
    byte_cnt = 0

    for pkt in pcap:
        if pkt.time <= time:
            byte_cnt = byte_cnt + len(pkt)
        else:
            print str(time - start) + "," + str(byte_cnt)
            byte_cnt = len(pkt)
            time = time + ST
