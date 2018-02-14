#!/usr/bin/python

import httplib
import json
import time

import constant as ct

PUSHER = None
FLOWSTAT = None
SWITCH_ID = ""

class FlowStat(object):
    def __init__(self, server):
        self.server = server

    def get(self, switch):
        path = '/wm/core/switch/'+switch+"/flow/json"
        ret = self.rest_call({}, 'GET', path)
        return json.loads(ret[2])

    def getSwitchDetails(self):
        path = '/wm/core/controller/switches/json'
        ret = self.rest_call({}, 'GET', path)
        return json.loads(ret[2])

    def rest_call(self, data, action, path):
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret

class StaticFlowPusher(object):
    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        conn.close()
        return ret

def initialize():
    global PUSHER, FLOWSTAT, SWITCH_ID

    PUSHER = StaticFlowPusher(ct.FLOWPUSHER_IP)
    FLOWSTAT = FlowStat(ct.FLOWPUSHER_IP)

    stat = FLOWSTAT.getSwitchDetails()

    # Get details of only the first switch
    try:
        print "Switch details:"
        print "IP : " + stat[0]["inetAddress"]
        print "Switch ID : " + stat[0]["switchDPID"]

        SWITCH_ID = stat[0]["switchDPID"]      
    except:
        print "Unable to get switch details" 
        PUSHER = None
        FLOWSTAT = None

def blockHost( name, blockIP ):
    global SWITCH_ID, PUSHER

    staticflow = {"switch":SWITCH_ID,
                  "name":name,
                  "cookie":"0",
                  "priority":"32700",
                  #"in_port":"1",
                  "eth_type":"0x800",
                  "ipv4_src":blockIP,
                  "active":"true"}

    PUSHER.set(staticflow)

    print "Blocking ", blockIP



if __name__ == '__main__':
    initialize()
    blockHost('Block', "192.168.137.179")

