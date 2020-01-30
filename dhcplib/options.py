import socket
import struct
import binascii


__all__ = (
    'DHCPOption', 'DHCPOption1', 'DHCPOption3', 'DHCPOption6', 'DHCPOption12',
    'DHCPOption15', 'DHCPOption50', 'DHCPOption51', 'DHCPOption53',
    'DHCPOption54', 'DHCPOption82'
)


class DHCPOption(object):
    """Base class for all DHCP _options."""

    HEADER_LEN = 2
    PAYLOAD_LEN_INDEX = 1
    OPTION_FORMAT = '!BB{}s'

    code = None
    length = None

    def __init__(self, value=None):
        self.value = value
        self._payload = b''

    def __str__(self):
        return '{}(LENGTH: {} VALUE: {})'.format(
            self.__class__.__name__, self.length, self.value
        )

    def __repr__(self):
        return self.__str__()

    def pack(self):
        if not self.length:
            self.length = len(self._payload)
        return struct.pack(
            self.OPTION_FORMAT.format(self.length),
            self.code,
            self.length,
            self._payload
        )

    @classmethod
    def from_bytes(cls, bytes_stream):
        code, length, payload = struct.unpack(
            cls.OPTION_FORMAT.format(bytes_stream[cls.PAYLOAD_LEN_INDEX]),
            bytes_stream
        )
        instance = cls()
        instance._payload = payload
        if not instance.length:
            instance.length = length
        return instance


class _DHCPOptionIP(DHCPOption):

    MIN_VALUE_LEN = 4

    def pack(self):
        if any(isinstance(self.value, cls_type) for cls_type in (tuple, list)):
            for value in self.value:
                self._payload += socket.inet_aton(str(value))
        else:
            self.length = self.MIN_VALUE_LEN
            self._payload = socket.inet_aton(str(self.value))
        return super(_DHCPOptionIP, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream):
        instance = super(_DHCPOptionIP, cls).from_bytes(bytes_stream)
        values = []
        for index in range(0, instance.length, cls.MIN_VALUE_LEN):
            values.append(
                socket.inet_ntoa(
                    instance._payload[index:index + cls.MIN_VALUE_LEN]
                )
            )
        instance.value = values if len(values) > 1 else values[0]
        return instance


class _DHCPOptionInt(DHCPOption):

    def pack(self):
        self._payload = self.value.to_bytes(self.length, byteorder='big')
        return super(_DHCPOptionInt, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream):
        instance = super(_DHCPOptionInt, cls).from_bytes(bytes_stream)
        instance.value = int.from_bytes(instance._payload, byteorder='big')
        return instance


class _DHCPOptionStr(DHCPOption):

    def pack(self):
        self._payload = self.value.encode('ascii')
        return super(_DHCPOptionStr, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream):
        instance = super(_DHCPOptionStr, cls).from_bytes(bytes_stream)
        instance.value = instance._payload.decode('ascii')
        return instance


class DHCPOption1(_DHCPOptionIP):

    code = 1
    length = 4


class DHCPOption3(_DHCPOptionIP):

    code = 3


class DHCPOption6(_DHCPOptionIP):

    code = 6


class DHCPOption12(_DHCPOptionStr):

    code = 12


class DHCPOption15(_DHCPOptionStr):

    code = 15


class DHCPOption50(_DHCPOptionIP):

    code = 50
    length = 4


class DHCPOption51(_DHCPOptionInt):

    code = 51
    length = 4


class DHCPOption53(_DHCPOptionInt):

    # Message types.
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPDECLINE = 4
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    DHCPINFORM = 8

    MESSAGE_TYPES = (
        DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK,
        DHCPRELEASE, DHCPINFORM
    )

    code = 53
    length = 1

    def __setattr__(self, key, value):
        if key == 'value' and value:
            if value not in self.MESSAGE_TYPES:
                raise ValueError('Invalid DHCP message type')
        super(DHCPOption53, self).__setattr__(key, value)


class DHCPOption54(_DHCPOptionIP):

    code = 54
    length = 4


class _DHCPSubOption82CircuitId(DHCPOption):

    code = 1

    def pack(self, encode_ascii=False):
        if not encode_ascii:
            try:
                self._payload = int(self.value).to_bytes(1, byteorder='big')
            except ValueError:
                self._payload = binascii.a2b_hex(self.value)
        else:
            self._payload = str(self.value).encode('ascii')
        return super(_DHCPSubOption82CircuitId, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream, encode_ascii=False):
        instance = \
            super(_DHCPSubOption82CircuitId, cls).from_bytes(bytes_stream)
        if not encode_ascii:
            instance.value = int.from_bytes(instance._payload, byteorder='big')
        else:
            instance.value = instance._payload.decode('ascii')
        return instance


class _DHCPSubOption82RemoteId(DHCPOption):

    code = 2

    def pack(self, encode_ascii=False):
        if not encode_ascii:
            self._payload = binascii.a2b_hex(self.value)
        else:
            self._payload = self.value.encode('ascii')
        return super(_DHCPSubOption82RemoteId, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream, encode_ascii=False):
        instance = super(
            _DHCPSubOption82RemoteId, cls
        ).from_bytes(bytes_stream)
        if not encode_ascii:
            instance.value = binascii.b2a_hex(
                instance._payload).decode('ascii')
        else:
            instance.value = instance._payload.decode('ascii')
        return instance


class DHCPOption82(DHCPOption):

    code = 82
    encode_ascii = False

    SUB_OPTIONS = {
        _DHCPSubOption82CircuitId.code: _DHCPSubOption82CircuitId,
        _DHCPSubOption82RemoteId.code: _DHCPSubOption82RemoteId
    }

    def __init__(self, circuit_id=None, remote_id=None):
        super(DHCPOption82, self).__init__()
        self.circuit_id = self._get_option_instance(_DHCPSubOption82CircuitId,
                                                    circuit_id)
        self.remote_id = self._get_option_instance(_DHCPSubOption82RemoteId,
                                                   remote_id)

    def __str__(self):
        return '{}(LENGTH: {}, VALUE: {})'.format(
            self.__class__.__name__,
            self.length,
            (self.circuit_id, self.remote_id)
        )

    @staticmethod
    def _get_option_instance(option_cls, value):
        if not value:
            return value
        return value if isinstance(value, option_cls) else option_cls(value)

    def pack(self):
        self._payload = self.circuit_id.pack(self.encode_ascii) + \
                        self.remote_id.pack(self.encode_ascii)
        return super(DHCPOption82, self).pack()

    @classmethod
    def from_bytes(cls, bytes_stream):
        instance = super(DHCPOption82, cls).from_bytes(bytes_stream)
        index = 0
        for _ in range(len(cls.SUB_OPTIONS)):
            payload_start_index = index + cls.HEADER_LEN
            sub_option_code, sub_option_length = struct.unpack(
                '!BB', instance._payload[index:payload_start_index]
            )
            sub_option_class = cls.SUB_OPTIONS.get(sub_option_code)
            if sub_option_class:
                sub_option = sub_option_class.from_bytes(
                    instance._payload[index:
                                      payload_start_index + sub_option_length],
                    encode_ascii=cls.encode_ascii
                )
                if sub_option.code == _DHCPSubOption82CircuitId.code:
                    instance.circuit_id = sub_option
                elif sub_option.code == _DHCPSubOption82RemoteId.code:
                    instance.remote_id = sub_option
            index = payload_start_index + sub_option_length
        return instance
