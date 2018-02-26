#!/usr/bin/python

import sys
import argparse

# Insert include path for modules
sys.path.insert(0, "lib")
sys.path.insert(0, "mod")
sys.path.insert(0, "etc")

# Import constant and module files
import constant as ct

def parseArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--controller", action="store_true", help="run controller module")
    parser.add_argument("-s", "--switch", action="store_true", help="run switch module")
    parser.add_argument("-t", "--train", action="store_true", help="run training module")

    return parser.parse_args()

if __name__ == '__main__':
    args = parseArguments()

    modules = ["modController", "modSwitch", "modTrain"]
    options = [args.controller, args.switch, args.train]
    mod = None

    for opt, module in zip(options, modules):
        if (opt):
            mod = __import__(module)
            mod.run()

    
    if not mod:
        print ("Choose a valid module. Check help for more details")
