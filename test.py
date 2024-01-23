import binascii

import util

if __name__ == "__main__":
    print(util.url2str(b'0802.%E6%96%87%E6%A1%88'))
    print(util.url2str(b'000%E6%96%87%E6%A1%880802.%E6%96%87%E6%A1%880000'))