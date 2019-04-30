def calc_checksum(f, int checksum_offset):
    cdef unsigned int checksum = 0
    cdef unsigned int size = 0
    cdef unsigned char* idata
    cdef int i = 0
    f.seek(0)

    # Read up until the checksum
    data = f.read(checksum_offset)
    idata = <unsigned char*>data
    for i in range(0, len(data) - len(data) % 2, 2):
        checksum += (idata[i+1] << 8) | idata[i]
        checksum = 0xFFFF & (checksum + (checksum >> 0x10))
        size += 2

    # Skip over the next 4 bytes
    f.read(4)
    for i in range(2):
        checksum = 0xFFFF & (checksum + (checksum >> 0x10))
        size += 2

    # Read the rest of the file
    while True:
        data = f.read(1024**2)
        idata = <unsigned char*>data
        if not data:
            break
        for i in range(0, len(data) - (len(data) % 2), 2):
            checksum += (idata[i+1] << 8) | idata[i]
            checksum = 0xFFFF & (checksum + (checksum >> 0x10))
            size += 2

    checksum = 0xFFFF & (checksum + (checksum >> 0x10))
    checksum += size
    checksum &= 0xFFFFFFFF
    return checksum
