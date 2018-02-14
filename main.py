#!/usr/bin/python

import sys
import argparse

# Insert include path for modules
sys.path.insert(0, "lib")
sys.path.insert(0, "mod")
sys.path.insert(0, "res")

# Import constant and module files
import constant as ct
import modController as controller
import modSwitch as switch
import modTrain as train


def parseArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--controller", action="store_true", help="run controller module")
    parser.add_argument("-s", "--switch", action="store_true", help="run switch module")
    parser.add_argument("-t", "--train", action="store_true", help="run training module")

    return parser.parse_args()

if __name__ == '__main__':
    args = parseArguments()

    if args.controller:
        controller.run()
    elif args.switch:
        switch.run()
    elif args.train:
        train.run()
    else:
        print "Choose a module to run. Check help for more details."
