#!/usr/bin/python
import time
import Queue
import threading
import logging
import os
import sys
from terminaltables import AsciiTable
from collections import OrderedDict
from subprocess import check_output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#Getting Useful information automatically
route = check_output(['route'])
gateaway,iface= (route.split()[i] for i in (18,17) )
#hostscanning import
from modules.hostscanning import *
from modules.portscanning import *
errorhandlingmessage = 'unknown port'
closed = 0
portlist = { 80: 'webserver'}

def is_up(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10, verbose=0)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True

def discover_hosts():
    hostscan()

def scan_ports():
    pscan()

def misc():

    print "[*] You did choose misc."
    print

def exit():
    print "[~] Exiting"
    sys.exit()


def get_user_choice(choices):
    choice = None
    while choice not in choices:
        for i, (name, _) in choices.items():
            print '%s. %s' % (i, name)
        choice = raw_input('> ').strip()
        if choice not in choices:
            print "[~]%s is not a valid Command " % choice
            print
            print

    return choice

print'''

  ___               _  _     _                  _     ___
 |_ _|__ ___ _  _  | \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _
  | |/ _/ -_) || | | .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___\__\___|\_, | |_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|
             |__/


'''

choices = OrderedDict((
    ('1', ('Host Discovery', discover_hosts)),
    ('2', ('Port Scanning', scan_ports)),
    ('3', ('Misc', misc)),
    ('4', ('Exit', exit))

))

while True:
    choice = get_user_choice(choices)
    choices[choice][1]()
