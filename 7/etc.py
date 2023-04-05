def generate_messages():
    ret = {}
    ret[0] = "test"
    return ret

def generate_c2i_mapper():
    ret = {}
    for i in range(ord('a'), ord('z')+1):
        ret[chr(i)] = i - ord('a')
    return ret

def generate_i2c_mapper():
    ret = {}
    for i in range(26):
        ret[i] = chr(i+97)
    return ret
