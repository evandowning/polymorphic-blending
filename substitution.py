#!/usr/bin/env python2
import struct
import math
import dpkt
import socket
from collections import Counter
from frequency import *
from random import random

def substitute(attack_payload, subsitution_table):
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)
    b_attack_payload = bytearray(attack_payload)
    #print len(b_attack_payload)
    result = []
    xor_table = []
    # Based on your implementattion of substitution table, please prepare result and xor_table as output

    for i, val in enumerate(attack_payload):
#   print i, val
        replacement = None
        subs = subsitution_table[val]
        running = 0
        total = 0
        for sub in subs:
            total += sub[1]
        rand = random() * total
        # print rand
        for sub in subs:
            running += sub[1]
            if rand <= running:
                replacement = sub[0]
                break
        result.append(replacement)
        xor_table.append(chr(ord(val) ^ ord(replacement)))

    return (xor_table, result)

def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack body by replacing the most frequent byte in attack body to the most frequency byte in artificial profile one by one

    # Note the frequency for each byte is provided below in dictionay format. Please check frequency.py for more details
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)

    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)
    #print sorted_artificial_frequency
    #print "hello"
    #print sorted_attack_frequency

    # Your code here ...

    # I am assuming a that len(sorted_artificial_frequency) >= len(sorted_attack_frequency)
    # AKA, the m <= n case described in the paper
    substitution_table = {}
    for i, val in enumerate(sorted_attack_frequency): #Do an inital one to one mapping
        #print i, val
        #print val[0]
        substitution_table[val[0]] = [sorted_artificial_frequency[i]]
    # print substitution_table
    # print len(substitution_table)
    for i in range(len(sorted_attack_frequency), len(sorted_artificial_frequency)): #Map the rest of the valid characters
        highestRatio = -1
        highest = None
        for key, val in substitution_table.iteritems():
            ratio = 0
            #print val
            for sub in val:
                ratio += sub[1]
                # print sub
            ratio = attack_frequency[key] / ratio
            if ratio > highestRatio:
                highestRatio = ratio
                highest = key
        substitution_table[highest].append(sorted_artificial_frequency[i])
    print substitution_table
    # You may implement substitution table in your way. Just make sure it can be used in substitute(attack_payload, subsitution_table)
    return substitution_table


def getAttackBodyPayload(path):
    f = open(path)
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if socket.inet_ntoa(ip.dst) == "192.150.11.111": # verify if the dst IP from your attack payload is same
            tcp = ip.data
            if tcp.data == "":
                continue
            return tcp.data.rstrip()

def getArtificialPayload(path):
    f = open(path)
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.sport == 80 and len(tcp.data) > 0: #MODIFY THE PORT NUMBERS FOR IRC TRAFFIC (Similar to what you did in read_pcap.py)
            return tcp.data
