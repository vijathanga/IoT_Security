# Controller constants
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 10000
FLOWPUSHER_IP = '172.16.132.233'

# Switch constants
CAPTURE_IFACE = "ens33"
CAPTURE_TIMEOUT = 2
CAPTURE_FILTER = 'tcp or icmp'


# Training constants
FEATURE_FILE = "./res/features_5s.csv"
SAMPLING_TIME = 2
PROTOCOL = ["TCP", "ICMP"]
APPEND_FEATURES = True
EXTRACT_FEATURES = False
PREDICTION = True


# Predictor constants
REGULARISATION = 1
TEST_SIZE = 0.3
CLASSIFIER_PATH = "res/clf/"
CLASSIFIER_FILE = ['linearSVM.pkl', 'rbfSVM.pkl', 'sigSVM.pkl', \
                    'gaussNB.pkl', 'multiNB.pkl', 'bernNB.pkl', 'mlp.pkl']
CLASSIFIER = 'linearSVM.pkl'



# Feature file constants
FEATURES = ["label", "prot", "syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr", "echoReq", "echoRply",
                     "meanArrTime", "varArrTime", "minArrTime", "maxArrTime", 
                     "meanPktLen",  "varPktLen",  "minBytes",   "maxBytes",   "totPkt", "totBytes"]

LABELS = ['Normal', 'TCP_Flood', 'ICMP_Flood' ]
TCP_FLOOD = 1; ICMP_FLOOD = 2

PCAPS = [
    {
        "label": TCP_FLOOD,
        "file": "res/pcap/TCP/TCP_Dlink_camera.pcap",
        "attackIP": "172.16.134.76",
        "attackProt": "TCP",
        "parse": True
    },
    {
        "label": TCP_FLOOD,
        "file": "res/pcap/TCP/TCP_Dlink_socket.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "TCP",
        "parse": False
    },
    {
        "label": TCP_FLOOD,
        "file": "res/pcap/TCP/TCP_TPlink_camera.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "TCP",
        "parse": False
    },
    {
        "label": TCP_FLOOD,
        "file": "res/pcap/TCP/TCP_TPlink_socket.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "TCP",
        "parse": False
    },
    {
        "label": ICMP_FLOOD,
        "file": "res/pcap/ICMP/ICMP_Dlink_camera.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "ICMP",
        "parse": False
    },
    {
        "label": ICMP_FLOOD,
        "file": "res/pcap/ICMP/ICMP_TPlink_camera.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "ICMP",
        "parse": False
    },
    {
        "label": ICMP_FLOOD,
        "file": "res/pcap/ICMP/ICMP_Dlink_socket.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "ICMP",
        "parse": False
    },
    {
        "label": ICMP_FLOOD,
        "file": "res/pcap/ICMP/ICMP_TPlink_socket.pcap",
        "attackIP": "192.168.137.179",
        "attackProt": "ICMP",
        "parse": False
    }
]
