cpdef unsigned int _checksum_update_fast(data, unsigned int checksum):
    cdef unsigned int val
    cdef unsigned int i
    cdef unsigned char[:] c_data = data
    for i in range(0, len(data), 2):
        val = (c_data[i + 1] << 8) | c_data[i]
        checksum += val
        checksum = 0xFFFF & (checksum + (checksum >> 0x10))
    return checksum
