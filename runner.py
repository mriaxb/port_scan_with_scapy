import argparse
import sys

import scanner as scanner
from scanner import scan


parser = argparse.ArgumentParser(prog='runner')
parser.add_argument('-p', '--ports', nargs=2, required=True, help='Port interval to scan')
parser.add_argument('-t', '--target', required=True, help='Target host')
parser.add_argument('-m', '--mode', nargs=1, required=True, help='scan mode: 1-syn, 2-fin, 3-ack ')


args = parser.parse_args()

try:
    beginPort = int(args.ports[0])
    endPort = int(args.ports[1])
    assert beginPort >= 0 and endPort >= 0 and beginPort <= endPort
except AssertionError:
    print ("[ERROR] The port range is invalid")
    sys.exit()


target = args.target
mode = args.mode

scan(target, beginPort, endPort, int(mode[0]))