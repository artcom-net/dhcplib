import datetime
import ipaddress

from .utils import is_iterable
from .message import DHCPMessage
from .udp import UDPServer
from .error import DHCPConfigInitError, DHCPServerInitError
from .options import (
    DHCPOption53, DHCPOption1, DHCPOption3, DHCPOption51, DHCPOption54,
    DHCPOption6, DHCPOption15
)


class DHCPServerConfig(object):
    """This class used for DHCPServer configuration."""

    EXCLUDED_PREFIX = (31, 32)

    def __init__(self, net, addr_range=None, dns=None, gateway=None,
                 domain=None, lease_time=3600, identifier=None):
        """DHCPServerConfig initial.

        :param net: string like 'ip/mask'. Mask maybe pass as prefix and
            ip notation.
        :param addr_range: tuple or list contains start and end addresses
        :param dns: tuple or list contains DNS servers address
        :param gateway: tuple or list contains gateways address
        :param domain: domain name
        :param lease_time: positive integer
        :param identifier: DHCP server identifier (option 54)

        """
        self.addr_range = None
        self.dns = None
        self.gateway = None
        self.identifier = ipaddress.IPv4Address(identifier or '0.0.0.0')
        self.domain = domain
        self.net = ipaddress.IPv4Network(net)

        if self.net.prefixlen in self.EXCLUDED_PREFIX:
            raise DHCPConfigInitError('Net prefix must be less than 31')

        self.excluded_addr = (
            self.net.network_address,
            self.net.broadcast_address,
            self.identifier
        )

        if addr_range:
            if not is_iterable(addr_range):
                raise DHCPConfigInitError(
                    'Address range must be iterable object'
                )
            if len(addr_range) != 2:
                raise DHCPConfigInitError(
                    'Address range must be contain two values'
                )

            _addr_range = tuple(ipaddress.IPv4Address(addr)
                                for addr in addr_range)

            if _addr_range[0] > _addr_range[1]:
                raise DHCPConfigInitError('Incorrect address range')
            if not all(map(self._check_ip, _addr_range)):
                raise DHCPConfigInitError('Incorrect address range')
            self.addr_range = _addr_range
        else:
            self.addr_range = (self.net[1], self.net.broadcast_address - 1)

        if dns:
            self.dns = self._init_ip_param(dns)

        if gateway:
            self.gateway = self._init_ip_param(dns)

        if not isinstance(lease_time, int):
            raise DHCPConfigInitError('Lease time must be "int" type')

        if lease_time <= 0:
            raise DHCPConfigInitError('Incorrect lease time')
        self.lease_time = lease_time

    def _check_ip(self, ip):
        if all(ip != addr for addr in self.excluded_addr) and ip in self.net:
            return True
        return False

    def _init_ip_param(self, param):
        if is_iterable(param):
            values = tuple(ipaddress.IPv4Address(val) for val in param)
            if not all(map(self._check_ip, values)):
                raise DHCPConfigInitError('Incorrect value {}'.format(values))
            return values
        value = ipaddress.IPv4Address(param)
        if not self._check_ip(value):
            raise DHCPConfigInitError('Incorrect value {}!'.format(value))
        return value


class DHCPServer(object):

    # Binding states.
    FREE = 0
    ACTIVE = 1
    OFFERED = 2

    def __init__(self, config, listen_port=67):
        """DHCPServer initial.

        :param config: DHCPServerConfig instance.

        """
        if not isinstance(config, DHCPServerConfig):
            raise DHCPServerInitError(
                'config must be DHCPServerConfig instance'
            )
        self.udp_server = UDPServer(listen_port, self.handler)
        self.config = config
        self.leases = {}
        self.options = [
            DHCPOption1(self.config.net.netmask.exploded),
            DHCPOption51(self.config.lease_time),
            DHCPOption54(self.config.identifier.exploded)
        ]
        if self.config.gateway:
            self.options.append(DHCPOption3(self.config.gateway))
        if self.config.dns:
            self.options.append(DHCPOption6(self.config.dns))
        if self.config.domain:
            self.options.append(DHCPOption15(self.config.domain))

    def start(self):
        try:
            self.udp_server.start_handle()
        except KeyboardInterrupt:
            self.udp_server.stop()
        exit(1)

    def handler(self, data):
        self._update_leases()
        payload, ip_port = data
        message = DHCPMessage.from_bytes(payload)

        dhcp_message_type = message.option53.value
        message_to_send = None

        if dhcp_message_type == DHCPOption53.DHCPDISCOVER:
            message_to_send = self.dhcp_discover_handler(message)
        elif dhcp_message_type == DHCPOption53.DHCPREQUEST:
            message_to_send = self.dhcp_request_handler(message)
        elif dhcp_message_type == DHCPOption53.DHCPRELEASE:
            self.dhcp_release_handler(message)
            return None
        elif dhcp_message_type == DHCPOption53.DHCPDECLINE:
            self.dhcp_decline_handler(message)
            return None
        elif dhcp_message_type == DHCPOption53.DHCPINFORM:
            pass

        if message_to_send:
            self.udp_server.send_data(message_to_send.pack(), ip_port[1])

    def _ip_range_generator(self):
        start_host, end_host = self.config.addr_range
        host = start_host
        while host <= end_host:
            yield host
            host += 1

    def _get_free_ip(self, chaddr, xid):
        for host in self._ip_range_generator():
            ip = host.exploded
            lease = self.leases.get(ip)
            time_end = datetime.datetime.now() + datetime.timedelta(seconds=60)
            if not lease:
                self.leases[ip] = {
                    'chaddr': chaddr,
                    'state': self.OFFERED,
                    '_xid': xid,
                    'end_time': time_end
                }
                return ip
            if lease['chaddr'] == chaddr or lease['state'] == self.FREE:
                lease.update(
                    chaddr=chaddr,
                    state=self.OFFERED,
                    xid=xid,
                    end_time=time_end
                )
                return ip
        return None

    def _get_lease(self, message, check_xid=True, req_ip=None):
        if message.option54.value != self.config.identifier:
            return None
        lease = self.leases.get(req_ip if req_ip else message.option50.value)
        if not lease:
            return None
        if check_xid and message.xid != lease['_xid']:
            return None
        if message.chaddr != lease['chaddr']:
            return None
        return lease

    def dhcp_discover_handler(self, message):
        yiaddr = self._get_free_ip(message.chaddr, message.xid)
        if not yiaddr:
            return None
        offer_message = DHCPMessage.from_message(
            message,
            op=DHCPMessage.BOOTREPLY,
            yiaddr=yiaddr,
            options=(DHCPOption53(DHCPOption53.DHCPOFFER), *self.options)
        )
        return offer_message

    def dhcp_request_handler(self, message):
        lease = self._get_lease(message)
        if lease:
            ack_message = DHCPMessage.from_message(
                message,
                op=DHCPMessage.BOOTREPLY,
                yiaddr=message.option50.value,
                options=(DHCPOption53(DHCPOption53.DHCPACK), *self.options)
            )
            dt_now = datetime.datetime.now()
            delta = datetime.timedelta(seconds=self.config.lease_time)
            lease.update(
                state=self.ACTIVE,
                start_time=dt_now,
                end_time=dt_now + delta
            )
            return ack_message
        return None

    def dhcp_release_handler(self, message):
        lease = self._get_lease(message, check_xid=False,
                                req_ip=message.ciaddr)
        if lease:
            lease['state'] = self.FREE

    def dhcp_decline_handler(self, message):
        lease = self._get_lease(message, check_xid=False)
        if lease:
            lease['state'] = self.ACTIVE

    def _update_leases(self):
        for lease in self.leases.values():
            if datetime.datetime.now() > lease['end_time']:
                lease['state'] = self.FREE
