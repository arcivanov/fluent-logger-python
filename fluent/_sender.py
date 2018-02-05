# -*- coding: utf-8 -*-

# Generally speaking, if 2.7 and 3.4 compatibility wasn't a requirement it would've been better to do with async
# Alas, we have to be backwards compatible so we're doing it the old-fashioned way

try:
    basestring
except NameError:  # pragma: no cover
    basestring = (str, bytes)
    unicode = str

from threading import RLock

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from collections import deque, OrderedDict as odict

import time
import sys
import os
import logging
from base64 import b64encode
from uuid import uuid1
from time import sleep
from os.path import abspath
from hashlib import sha512
from msgpack import Unpacker, Packer
from queue import Queue
from msgpack.fallback import Unpacker
from threading import Thread
import socket
from select import select
from errno import EWOULDBLOCK, EINPROGRESS
from subprocess import Popen

if sys.platform == "win32" and sys.version_info[:2] < (3, 5):
    import backport.socketpair

    backport.socketpair  # ensure it's not optimized out

DEFAULT_SCHEME = "tcp"

CLOSED = b""
EOF = CLOSED
NEW_OP = b"0"

OP_READ = 1
OP_WRITE = 2
OP_CLOSE = 3

EPC_READY = 0
EPC_HELO = 1
EPC_PONG = 2

TOMBSTONE = object()

_endpoint_registry = {}


def to_bytes(s):
    if isinstance(s, unicode):
        return s.encode("utf-8")
    return s


def _register_endpoint(schemes, endpoint, force_overwrite=False):
    if isinstance(schemes, basestring):
        schemes = (schemes,)

    for scheme in schemes:
        if scheme in _endpoint_registry and not force_overwrite:
            raise RuntimeError("endpoint %s is already registered with %r" % (scheme, endpoint))
        _endpoint_registry[scheme] = endpoint


def _find_endpoint(scheme):
    """
    ``scheme`` - ``Endpoint`` only handles ``scheme``
    ``scheme``+``subscheme`` - ``Endpoint`` only handles that specific chain of schemes overwriting the wildcard
    ``scheme``+ - ``Endpoint`` handles all schemes that start with ``scheme``
    :param scheme:
    :return:
    """
    endpoint = _endpoint_registry.get(scheme)
    if not endpoint:
        for r_scheme in _endpoint_registry:
            if r_scheme[-1] == "+" and scheme == r_scheme[:-1] or scheme.startswith(r_scheme):
                endpoint = _endpoint_registry[r_scheme]
                break

    return endpoint


def endpoint(url, **kwargs):
    p_url = urlparse(url, scheme=DEFAULT_SCHEME)
    endpoint = _find_endpoint(p_url.scheme)
    if not endpoint:
        raise ValueError("No endpoint found for %s" % url)

    return endpoint(**kwargs)


class Endpoint:
    """And endpoint is a single FluentD server or a server cluster that operates cohesively as one unit.
    Endpoint may have multiple ``EndpointConnection``s that may come and go as cluster nodes are spun up and die.

    """

    def __init__(self, shared_key=None, username=None, password=None):
        self.connections = odict()
        self.sender_c = None

        self.shared_key = shared_key
        self.username = username
        self.password = password

        self.self_fqdn = to_bytes(socket.getfqdn())

    def attach(self, sender_c):
        self.sender_c = sender_c

    def protocol(self):
        pass

    def addrs(self):
        """Returns all socket addresses """
        pass

    def connection(self):
        return EndpointConnection

    def refresh_connections(self):
        """Called by SenderConnection when it's time to refresh the connections"""

        s_addrs = set(self.addrs())

        removed_addrs = self.connections.keys() - s_addrs
        new_addrs = s_addrs - self.connections.keys()

        for addr in removed_addrs:
            self.connections.pop(addr).close()

        for new_addr in new_addrs:
            conn = self.connection()(new_addr, self)
            self.connections[new_addr] = conn
            conn.connect()

        return removed_addrs, new_addrs


class EndpointConnection(Thread):
    """One of the connections established for a specific ``Endpoint``. """

    def __init__(self, addr, endpoint):
        super(EndpointConnection, self, ).__init__(name="EP %r" % (addr,), daemon=True)

        self.addr = addr
        self.endpoint = endpoint
        self.logger = endpoint.sender_c.logger
        self.sender_c = endpoint.sender_c
        self.sock = self._socket(addr)  # type: socket.socket
        self._fileno = self.sock.fileno()
        self._unpacker = None
        self._eventq = Queue()  # queue of messages to be processed by the connection, in order
        self._writeq = deque()  # data to be written into a socket, in order

        self._shared_key_salt = None
        self._nonce = None
        self._keep_alive = False

        if endpoint.shared_key or endpoint.username:
            self.state = EPC_HELO
        else:
            self.state = EPC_READY

    def connect(self):
        self.sock.setblocking(False)
        addr = self._connect_addr()
        self.logger.debug("Establishing connection to %s", addr)
        self._connect(addr)
        self._fileno = self.sock.fileno()
        self.start()

    def fileno(self):
        return self._fileno

    def on_read(self):
        try:
            data = self._recv()
        except socket.error as e:
            if e.errno == EWOULDBLOCK or e.errno == EINPROGRESS:
                return True
            raise

        if data == b"\x00":
            # This is just HEARTBEAT, skip
            logger.debug("Received HEARTBEAT from %s", self._connect_addr)
            return True

        unpacker = self._unpacker
        if not unpacker:
            unpacker = self._unpacker = Unpacker(encoding='utf-8')

        unpacker.feed(data)
        obj = None
        for obj in unpacker:
            self.logger.debug("On %s received: %s", self, obj)
            self._eventq.put(obj)

        self._unpacker = None

        if obj is None and data == EOF:
            if self._keep_alive:
                log = self.logger.warning
            else:
                log = self.logger.debug
            log("Connection %s remote closed while reading", self)

            self.schedule_close()
            return False

        return True

    def on_write(self):
        try:
            data = self._writeq.popleft()
        except IndexError:
            return False

        bytes_left = len(data)
        bytes_sent = -1
        while bytes_left and bytes_sent:
            try:
                bytes_sent = self._send(data)
                if not bytes_sent:
                    self.logger.warning("Connection %s remote closed unexpectedly while writing", self)
                    self.schedule_close()
                    return False
                bytes_left -= bytes_sent
                if bytes_left:
                    data = data[bytes_sent:]
            except socket.error as e:
                if e.errno == EWOULDBLOCK:
                    break
                raise

        if bytes_left:  # We tried to write everything but couldn't and received a 0-byte send
            self._writeq.appendleft(data)

        return True

    def schedule_close(self):
        self.logger.debug("Scheduling close on %s", self)
        self.sender_c.schedule_op(OP_CLOSE, self)

    def close(self):
        if self.sock.fileno() < 0:
            return

        self.logger.debug("Closing %s", self)
        self.sender_c.schedule_op(OP_READ, self, False)
        self.sender_c.schedule_op(OP_WRITE, self, False)
        try:
            try:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except socket.error:  # pragma: no cover
                    pass
            finally:
                try:
                    self.sock.close()
                except socket.error:  # pragma: no cover
                    pass
        finally:
            self._eventq.put(TOMBSTONE)

    def send(self, data):
        self._writeq.append(data)
        self.sender_c.schedule_op(OP_WRITE, self)

    def ping_from_helo(self, obj):
        shared_key_salt = None
        shared_key_hexdigest = None
        password_digest = ""

        self._keep_alive = obj[1].get("keepalive", False)

        if self.endpoint.shared_key:
            self._shared_key_salt = shared_key_salt = os.urandom(16)
            self._nonce = nonce = obj[1]["nonce"]
            digest = sha512()
            digest.update(shared_key_salt)
            digest.update(self.endpoint.self_fqdn)
            digest.update(nonce)
            digest.update(to_bytes(self.endpoint.shared_key))
            shared_key_hexdigest = digest.hexdigest()

        if self.endpoint.username:
            digest = sha512()
            digest.update(obj[1]["auth"])
            digest.update(to_bytes(self.endpoint.username))
            digest.update(to_bytes(self.endpoint.password))
            password_digest = digest.hexdigest()

        data = ["PING", self.endpoint.self_fqdn, shared_key_salt, shared_key_hexdigest,
                self.endpoint.username or "", password_digest]
        msg = Packer(use_bin_type=True).pack(data)
        return msg

    def verify_pong(self, obj):
        try:
            if not obj[1]:
                self.logger.warning("Authentication failed for %s: %s", self, obj[2])
                return False
            else:
                # Authenticate server
                digest = sha512()
                digest.update(self._shared_key_salt)
                digest.update(to_bytes(obj[3]))
                digest.update(self._nonce)
                digest.update(to_bytes(self.endpoint.shared_key))
                my_shared_key_hexdigest = digest.hexdigest()
                if my_shared_key_hexdigest != obj[4]:
                    self.logger.warning("Server hash didn't match: %r vs %r", my_shared_key_hexdigest, obj[4])
                    return False
                return True
        except Exception as e:
            self.logger.error("Unknown error while validating PONG", exc_info=e)
            return False

    def send_msg(self, tag, time, record, ack=False):
        options = {"size": 1}
        if ack:
            options["chunk"] = b64encode(uuid1().bytes)
        data = [tag, int(time), record, options]
        self.logger.debug("Sending %r", data)
        msg = Packer(use_bin_type=True).pack(data)
        self.send(msg)

    def send_msgs(self, tag, entries, ack=False):
        options = {"size": len(entries)}
        if ack:
            options["chunk"] = b64encode(uuid1().bytes)
        data = [tag, entries, options]
        self.logger.debug("Sending %r", data)
        msg = Packer(use_bin_type=True).pack(data)
        self.send(msg)

    def run(self):
        eventq = self._eventq
        while True:
            obj = eventq.get(block=True)
            if obj is TOMBSTONE:
                return
            if not obj:
                logger.warning("Unexpected empty packet received from %s: %s", self.sock.getpeername(), obj)
                self.close()
                return
            if isinstance(obj, (list, tuple)):  # Array
                msg_type = obj[0]
                if msg_type == "HELO":
                    if self.state != EPC_HELO:
                        logger.warning("Unexpected HELO received from %s: %s", self.sock.getpeername(), obj)
                        self.close()
                        return
                    self.send(self.ping_from_helo(obj))
                    self.state = EPC_PONG
                elif msg_type == "PONG":
                    if self.state != EPC_PONG:
                        logger.warning("Unexpected PONG received from %s: %s", self.sock.getpeername(), obj)
                        self.close()
                        return
                    if not self.verify_pong(obj):
                        self.close()
                        return
                    self.state = EPC_READY
                    self.logger.info("Ready!")
            else:  # Dict
                chunk_id = obj.get("ack", None)
                if not chunk_id:
                    logger.warning("Unexpected response received from %s: %s", self.sock.getpeername(), obj)
                    self.close()
                    return
                self.sender_c._ack_chunk(chunk_id)

    def _socket(self, addr):
        raise NotImplementedError

    def _connect_addr(self):
        raise NotImplementedError

    def _connect(self, addr):
        raise NotImplementedError

    def _recv(self):
        raise NotImplementedError

    def _send(self, data):
        raise NotImplementedError


class StreamConnection(EndpointConnection):
    def __init__(self, addr, endpoint, bufsize):
        if addr[1] != socket.SOCK_STREAM:
            raise ValueError("Socket type %s cannot be used with %s" % (addr[1], self.__class__.name))
        super(StreamConnection, self).__init__(addr, endpoint)
        self.bufsize = bufsize

    def _socket(self, addr):
        return socket.socket(addr[0], addr[1], addr[2])

    def _connect_addr(self):
        return self.addr[4]

    def _connect(self, addr):
        try:
            self.sock.connect(addr)
        except socket.error as e:
            if not (e.errno == EWOULDBLOCK or e.errno == EINPROGRESS):
                raise

    def _recv(self):
        return self.sock.recv(self.bufsize)

    def _send(self, data):
        return self.sock.send(data)


class TcpConnection(StreamConnection):
    def __init__(self, addr, endpoint, bufsize):
        if addr[0] not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("Address family %s cannot be used with %s" % (addr[0], self.__class__.name))
        super(TcpConnection, self).__init__(addr, endpoint, bufsize)


if False:  # pragma: no branch
    class UdpConnection(EndpointConnection):
        def __init__(self, addr, endpoint, maxsize, bind_to):
            if addr[1] != socket.SOCK_DGRAM:
                raise ValueError("Socket type %s cannot be used with %s" % (addr[1], self.__class__.name))
            super(UdpConnection, self).__init__(addr, endpoint)
            self.maxsize = maxsize
            self.bind_to = bind_to
            self.remote_addr = self.addr[4]

        def _socket(self, addr):
            return socket.socket(addr[0], addr[1], addr[2])

        def _connect_addr(self):
            return self.remote_addr

        def _connect(self, addr):
            self.sock.bind((self.bind_to, 0))
            self.sock.connect(self.remote_addr)

        def _recv(self):
            data, _ = self.sock.recvfrom(self.maxsize)
            return data

        def _send(self, data):
            return self.sock.sendto(data, self.remote_addr)


class UnixConnection(StreamConnection):
    def __init__(self, addr, endpoint, bufsize):
        if addr[0] != socket.AF_UNIX:
            raise ValueError("Address family %s cannot be used with %s" % (addr[0], self.__class__.name))
        super(UnixConnection, self).__init__(addr, endpoint, bufsize)

    def _socket(self, addr):
        return socket.socket(addr[0], addr[1])


class SenderConnection(Thread):
    def __init__(self, endpoints, ha_strategy, refresh_period, logger):
        """
        Internal Sender connection that maintains an aggregate connection for the Sender.
        The Sender may be connected to various servers and clusters via different protocols over multiple endpoints.
        How endpoints are treated depends on a strategy specified, which is transparent to the Sender.

        :param endpoints: iterable of Endpoint
        :param ha_strategy: a
        :param logger: internal Fluent logger
        """
        super(SenderConnection, self).__init__(name=self.__class__.name, daemon=True)

        self.endpoints = endpoints
        self.ha_strategy = ha_strategy
        self.logger = logger

        self.endpoint_connections = {}

        self._close_pending = deque()
        self._open_pending = deque()

        self.mutex = RLock()

        self.wakeup_sock_r, self.wakeup_sock_w = socket.socketpair()
        self.wakeup_sock_r.setblocking(False)

        self.op_queue = deque()

    def refresh_endpoints(self):
        for endpoint in self.endpoints:
            endpoint.refresh_connections()

    def schedule_op(self, op, conn, enable=True):
        self.op_queue.append((enable, op, conn))
        self.wakeup_sock_w.send(NEW_OP)

    def close(self, timeout=None):
        self.wakeup_sock_w.close()
        self.join(timeout)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _ack_chunk(self, chunk_id):
        logger.debug("Acknowledging chunk %r", chunk_id)

    def run(self):
        logger = self.logger
        r_int = set()
        w_int = set()

        wakeup_sock_r = self.wakeup_sock_r
        r_int.add(wakeup_sock_r)

        op_queue = self.op_queue

        with wakeup_sock_r, self.wakeup_sock_w:
            while r_int or w_int:
                r_ready, w_ready, _ = select(r_int, w_int, ())
                for r in r_ready:
                    if r is wakeup_sock_r:
                        while True:
                            try:
                                cmds = r.recv(4096)
                            except socket.error as e:
                                if e.errno == EWOULDBLOCK:
                                    break
                            if cmds == b"":
                                r_int.remove(r)
                                break
                            # Handle exception here
                            for cmd in cmds:
                                cmd = bytes((cmd,))
                                if cmd == CLOSED:
                                    r_int.remove(r)
                                    break
                                elif cmd == NEW_OP:
                                    enable, op, conn = op_queue.pop()  # type: EndpointOp
                                    if op == OP_READ:
                                        if enable:
                                            r_int.add(conn)
                                        else:
                                            r_int.discard(conn)
                                    elif op == OP_WRITE:
                                        if enable:
                                            w_int.add(conn)
                                        else:
                                            w_int.discard(conn)
                                    elif op == OP_CLOSE:
                                        conn.close()
                    else:
                        keep = False
                        try:
                            keep = r.on_read()
                        except Exception as e:
                            with r:
                                logger.warning("Read error on %s", r, exc_info=e)

                        if not keep:
                            r_int.remove(r)

                for w in w_ready:
                    keep = False
                    try:
                        keep = w.on_write()
                    except Exception as e:
                        with w:
                            logger.warning("Write error on %s", w, exc_info=e)

                    if not keep:
                        w_int.remove(w)

                r_ready.clear()
                w_ready.clear()


if __name__ == '__main__':
    logger = logging.getLogger("fluent")
    logger.propagate = False
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(1)

    with Popen(["docker", "run", "-i",
                "-p", "24224:24224", "-p", "24224:24224/udp",
                "-p", "24225:24225", "-p", "24225:24225/udp",
                "-p", "24226:24226", "-p", "24226:24226/udp",
                "-v", "%s:/fluentd/log" % abspath("../tests"),
                "-v", "%s:/fluentd/etc/fluent.conf" % abspath("../tests/fluent.conf"),
                "-v", "%s:/var/run/fluent" % abspath("../tests/fluent_sock"),
                "fluent/fluentd:v1.1.0"]) as docker:
        sleep(5)
        with SenderConnection([], None, None, logger) as conn:
            ep1 = Endpoint()
            ep2 = Endpoint(shared_key="abcd1234")
            ep3 = Endpoint(shared_key="1234abcd", username="foo", password="bar")
            ep1.attach(conn)
            ep2.attach(conn)
            ep3.attach(conn)

            epc1 = TcpConnection(
                (socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 ("127.0.0.1", 24224)),
                ep1, 16384)
            # epc2 = UdpConnection(
            #    (socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_DGRAM, socket.IPPROTO_UDP, "",
            #     ("127.0.0.1", 24225)),
            #    ep2, 8192, "0.0.0.0")
            unix_path = abspath("../tests/fluent_sock/fluent.sock")
            epc3 = UnixConnection(
                (socket.AddressFamily.AF_UNIX, socket.SocketKind.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 unix_path),
                ep3, 16384)

            for epc in (epc1, epc3):
                epc.connect()
                conn.schedule_op(OP_READ, epc)
                epc.send_msg("tag-name", time.time(), {"value-x": "a", "value-y": 1}, ack=True)
                epc.send_msgs("tag-name", ((int(time.time()), {"value-x": "a", "value-y": 1}),
                                           (int(time.time()), {"value-x": "m", "value-b": 200})), ack=True)
                sleep(3)
                epc.close()

        docker.terminate()
