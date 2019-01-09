#!/usr/bin/env python2
import struct
from collections import Counter

def sorting(dictFrequency):
    result = sorted(dictFrequency.items(), lambda x, y: cmp(x[1], y[1]), reverse = True)
    return result

def frequency(payload):
    c = Counter(payload)

    number = 0.0
    for (k,n) in  dict(c).items():
        number = number + n
    #print number

    result = {}
    for (k,n) in  dict(c).items():
        result.update({k:round(n/number,3)})
    #print result
    return result
