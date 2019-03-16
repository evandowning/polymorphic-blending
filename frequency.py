from collections import Counter

def sorting(freq):
    result = sorted(freq.items(), lambda x, y: cmp(x[1], y[1]), reverse = True)
    return result

def frequency(payload):
    c = Counter(payload)

    number = 0.0
    for (k,n) in c.items():
        number = number + n

    result = dict()
    for (k,n) in c.items():
        result.update({k:round(n/number,3)})

    return result
