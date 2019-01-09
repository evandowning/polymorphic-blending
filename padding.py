#!/usr/bin/env python2
import struct
import math
import random
from frequency import *
from collections import Counter

def padding(artificial_payload, raw_payload):
	padding = ""
	# Get frequency of raw_payload and artificial profile payload
	artificial_frequency = frequency(artificial_payload)
	raw_payload_frequency = frequency(raw_payload)

	highest = None
	highestDiff = 0
	for key, diff in artificial_frequency.iteritems():
		if raw_payload_frequency.has_key(key):
			diff -= raw_payload_frequency[key]
		if diff >= highestDiff:
			highestDiff = diff
			highest = key
	raw_payload.append(highest)