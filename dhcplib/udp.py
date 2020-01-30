import socket


class BaseUDPBroadcastServer(object):

    BUFFER = 1024

    def __init__(self, listen_port, timeout=None):
        self._listen_port = listen_port
        self._timeout = timeout

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.settimeout(self._timeout)
        self._sock.bind(('', self._listen_port))

    def send_data(self, data, port):
        self._sock.sendto(data, ('<broadcast>', port))

    def received_data(self):
        return self._sock.recvfrom(self.BUFFER)

    def stop(self):
        self._sock.close()


class UDPServer(BaseUDPBroadcastServer):

    def __init__(self, listen_port, proto_handler, timeout=None):
        super(UDPServer, self).__init__(listen_port, timeout)
        self._proto_handler = proto_handler

    def start_handle(self):
        while True:
            self._proto_handler(self.received_data())
