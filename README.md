# polymorphic-blending
Implements polymorphic blending attack on PAYL

Produces attack payload contents which would have been extracted from a pcap file

## Requirements
  * Debian 9 64-bit

## Install dependencies
```
$ sudo ./setup.sh
```

## Usage
```
# configure settings
$ vi pba.cfg

# Run polymorphic blending attack
$ python pba.py pba.cfg

# check that payload is correct
$ cd verify/; make; ./a.out; cd ..
# If you see the attack in plaintext ASCII
# characters, then the attack was crafted properly
```
