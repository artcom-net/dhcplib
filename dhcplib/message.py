import re
import struct
import socket
import binascii
from random import randint

from .options import *


MAX_UINT = 1 << 32


def _load_options():
    """Loads options from the global scope and return it as dictionary."""
    options_dict = {}
    for key, value in globals().copy().items():
        if re.match(r'^DHCPOption\d{1,3}', key):
            options_dict[value.code] = value
    return options_dict


class DHCPMessage(object):
    """This class to represent the DHCP message."""

    HEADER_LEN = 240
    HEADER_FORMAT = '!4B I 2H 4s 4s 4s 4s 16s 64s 128s 4B'

    # Message types.
    BOOTREQUEST = 1
    BOOTREPLY = 2

    # Adress types.
    ETHERNET = 1
    IEEE802 = 6

    # Flags.
    UNICAST_FLAG = 0
    BROADCAST_FLAG = 32768

    MAGIC_COOKIE = (99, 130, 83, 99)
    ENCODING = 'ascii'
    BYTE_ORDER = 'big'
    OPTIONS = _load_options()
    END_OPTIONS_FLAG = 255

    def __init__(
            self, op, htype=ETHERNET, hlen=6, hops=0, xid=None, secs=0,
            flags=BROADCAST_FLAG, ciaddr='0.0.0.0', yiaddr='0.0.0.0',
            siaddr='0.0.0.0', giaddr='0.0.0.0', chaddr='00:00:00:00:00:00',
            sname='', file='', options=None):
        """ DHCP message initial.

        :param op: Message op code / message type.
        :param htype: Hardware address type.
        :param hlen: Hardware address length.
        :param hops: Used by relay agents.
        :param xid: Transaction ID, a random number.
        :param secs: Seconds elapsed since client.
        :param flags: Flags.
        :param ciaddr: Client IP address.
        :param yiaddr: 'your' (client) IP address.
        :param siaddr: IP address of next server.
        :param giaddr: Relay agent IP address.
        :param chaddr: Client hardware address.
        :param sname: Optional server host name.
        :param file: Boot file name.
        :param options: Optional parameters field.

        """
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = xid or randint(1, MAX_UINT)
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.file = file
        self._options = {}
        if options:
            self._options = {option.code: option for option in options}

    def __getattr__(self, field):
        match = re.match(r'^option(\d{1,3})', field)
        if match:
            option = self._options.get(int(match.group(1)))
            return option if option else None
        raise AttributeError(
            "'{}' object has no attribute '{}'".format(
                self.__class__.__name__, field
            )
        )

    @classmethod
    def from_message(cls, message, **kwargs):
        message.__dict__.update(kwargs)
        return cls(**message.__dict__)

    @classmethod
    def from_bytes(cls, bytes_stream):
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, \
        giaddr, chaddr, sname, file, _ = struct.unpack(
            cls.HEADER_FORMAT,
            bytes_stream[:cls.HEADER_LEN]
        )
        instance = cls(op, htype, hlen, hops, xid, secs, flags)
        instance.ciaddr = socket.inet_ntoa(ciaddr)
        instance.yiaddr = socket.inet_ntoa(yiaddr)
        instance.siaddr = socket.inet_ntoa(siaddr)
        instance.giaddr = socket.inet_ntoa(giaddr)
        instance.chaddr = ':'.join(
            '{:02X}'.format(octet)
            for octet in struct.unpack('!{}B'.format(hlen), chaddr[:hlen])
        )
        instance.sname = sname.decode(cls.ENCODING)
        instance.file = file.decode(cls.ENCODING)
        instance._options = cls._parse_options(bytes_stream[cls.HEADER_LEN:])
        return instance

    @staticmethod
    def _parse_options(bytes_stream):
        options = {}
        index = 0
        end_options_flag_index = bytes_stream.rfind(
            DHCPMessage.END_OPTIONS_FLAG
        )
        while index < end_options_flag_index:
            payload_start_index = index + DHCPOption.HEADER_LEN
            code, length = struct.unpack(
                '!BB', bytes_stream[index: payload_start_index]
            )
            option_class = DHCPMessage.OPTIONS.get(code)
            if option_class:
                option = option_class.from_bytes(
                    bytes_stream[index:payload_start_index + length]
                )
                options[option.code] = option
            index = payload_start_index + length
        return options

    def pack(self):
        return self._pack_header() + self._pack_options()

    def _pack_header(self):
        return struct.pack(
            self.HEADER_FORMAT,
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            socket.inet_aton(self.ciaddr),
            socket.inet_aton(self.yiaddr),
            socket.inet_aton(self.siaddr),
            socket.inet_aton(self.giaddr),
            binascii.a2b_hex(self.chaddr.replace(':', '')),
            self.sname.encode(self.ENCODING),
            self.file.encode(self.ENCODING),
            *self.MAGIC_COOKIE
        )

    def _pack_options(self):
        return b''.join(
            option.pack() for option in self._options.values()
        ) + self.END_OPTIONS_FLAG.to_bytes(1, byteorder=self.BYTE_ORDER)
