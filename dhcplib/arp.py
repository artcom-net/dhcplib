import struct


class ARPFrame(object):

    # Hardware types.
    ETHERNET = 1

    # Protocol types.
    IP_PROTOCOL = 2048

    # Operation codes.
    REQUEST = 1
    REPLY = 2

    def __init__(self, operation, sha, spa, tpa, tha=0, htype=None, ptype=None,
                 hlen=6, plen=4):
        self.htype = htype or self.ETHERNET
        self.ptype = ptype or self.IP_PROTOCOL
        self.hlen = hlen
        self.plen = plen
        self.operation = operation
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa

    def dump_frame(self):
        return struct.pack(
            '!HHBBH6s4s6s4s',
            self.htype,
            self.ptype,
            self.hlen,
            self.plen,
            self.operation,
            self.sha,
            self.spa,
            self.tha,
            self.tpa
        )
