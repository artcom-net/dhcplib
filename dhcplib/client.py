import socket

from .utils import get_local_mac
from .message import DHCPMessage
from .udp import BaseUDPBroadcastServer
from .options import DHCPOption53, DHCPOption50


class DHCPClient(object):

    def __init__(self, server_port=67, listen_port=68, mac=None, timeout=5,
                 repeat_count=3, options=None):
        """DHCPClient initial.

        :param options: iterable object contains DHCPOption instances

        """
        self._server_port = server_port
        self._udp_server = BaseUDPBroadcastServer(listen_port, timeout=timeout)
        self._mac = mac or get_local_mac()
        self._repeat_count = repeat_count
        self._options = list(options) if options else []
        self._xid = None
        self._server_identifier = None

    def _send_dhcp_message(self, message):
        for _ in range(self._repeat_count):
            self._udp_server.send_data(message.pack(), self._server_port)
            try:
                payload, ip_port = self._udp_server.received_data()
            except socket.timeout:
                continue
            break
        else:
            return None
        return DHCPMessage.from_bytes(payload)

    def _get_request_message(self, **kwargs):
        return DHCPMessage(DHCPMessage.BOOTREQUEST, chaddr=self._mac, **kwargs)

    def send_dhcp_discover(self):
        options = self._options.copy()
        options.append(DHCPOption53(DHCPOption53.DHCPDISCOVER))
        message = self._get_request_message(options=options)
        self._xid = message.xid
        received_message = self._send_dhcp_message(message)
        if received_message.xid != self._xid:
            return None
        if received_message.option53.value != DHCPOption53.DHCPOFFER:
            return None
        return received_message

    def send_dhcp_request(self, offer_message):
        options = self._options.copy()
        self._server_identifier = offer_message.option54
        options.extend((
            DHCPOption53(DHCPOption53.DHCPREQUEST),
            DHCPOption50(offer_message.yiaddr),
            self._server_identifier
        ))
        message = self._get_request_message(xid=self._xid,
                                            options=options)
        received_message = self._send_dhcp_message(message)
        if received_message.xid != self._xid:
            return None
        if received_message.option54.value != self._server_identifier.value:
            return None
        return received_message

    def start(self):
        offer_message = self.send_dhcp_discover()
        if not offer_message:
            return None
        ack_message = self.send_dhcp_request(offer_message)
        if not ack_message:
            return None
        return ack_message
