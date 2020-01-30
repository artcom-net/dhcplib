import fcntl
import errno
import socket
import struct
from uuid import getnode
from random import randint


SIOCGIFADDR = 0x8915


def get_ip_by_iface(iface):
    """Returns an IP address which is bound to the 'iface'.

    :param iface: name of network adapter

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ifreq = struct.pack(
        '16sH14s', iface.encode('ascii'), socket.AF_INET, b'\x00' * 14
    )
    try:
        res = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
    except OSError as error:
        sock.close()
        if error.errno == errno.ENODEV:
            raise OSError('No such device: {}'.format(iface))
        raise error
    sock.close()
    return socket.inet_ntoa(struct.unpack('16sH2x4s8x', res)[2])


def is_iterable(value):
    if any(isinstance(value, cls) for cls in (tuple, list)):
        return True
    return False


def get_local_mac():
    bytes_list = []
    mac = hex(getnode())[2:].zfill(12)
    for index in range(0, 12, 2):
        bytes_list.append(mac[index:index + 2])
    return ':'.join(bytes_list)


def gen_random_mac():
    return ':'.join(
        '{:02X}'.format(randint(0, 255)) for _ in range(6)
    )
