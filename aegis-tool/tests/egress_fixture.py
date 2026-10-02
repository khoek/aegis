#!/usr/bin/env python3
"""Local DNS/HTTPS/control-plane fixtures for the isolated kernel test; no external I/O."""
import argparse
import http.server
import ipaddress
import json
import socket
import socketserver
import ssl
import struct
import threading
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('mode', choices=['internet', 'dns', 'api'])
p.add_argument('--directory', required=True)
p.add_argument('--ipv4')
p.add_argument('--ipv6')
a = p.parse_args()
directory = Path(a.directory)

class HTTP6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if a.mode == 'internet':
            return self.reply(200, {'exit': self.client_address[0]})
        inventory = json.loads((directory / 'inventory.json').read_text())
        if self.path.endswith('/egress'):
            return self.reply(200, inventory)
        source = self.path.rsplit('/', 1)[-1]
        return self.reply(200, self.status(inventory, source))

    def status(self, inventory, source):
        return dict(source_host_id=source, aliases=inventory['hosts'][source]['aliases'],
                    config=inventory['config'], policy=inventory['policies'].get(source))

    def do_PUT(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        inventory = json.loads((directory / 'inventory.json').read_text())
        source = self.path.rsplit('/', 1)[-1]
        before = inventory['policies'].get(source)
        if before and before['desired_via'] == data['via']:
            return self.reply(200, self.status(inventory, source))
        policy = dict(source_host_id=source, revision=(before['revision'] if before else 0) + 1,
                      active_via=before['active_via'] if before else None, desired_via=data['via'],
                      updated_unix=1, updated_by_principal='fixture-user')
        inventory['policies'][source] = policy
        (directory / 'inventory.json').write_text(json.dumps(inventory))
        self.reply(202, self.status(inventory, source))

    def do_DELETE(self):
        inventory = json.loads((directory / 'inventory.json').read_text())
        source = self.path.rsplit('/', 1)[-1]
        policy = inventory['policies'].get(source)
        if policy:
            policy['revision'] += 1
            policy['desired_via'] = None
        (directory / 'inventory.json').write_text(json.dumps(inventory))
        self.reply(202 if policy else 204, {})

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if (directory / 'reject-report').exists():
            return self.reply(503, {'error': 'injected reporting outage'})
        inventory = json.loads((directory / 'inventory.json').read_text())
        source = self.path.split('/')[-2]
        policy = inventory['policies'].get(source)
        if not policy or policy['revision'] != data['revision']:
            return self.reply(409, {'error': 'stale operation'})
        via = policy['desired_via'] if data['outcome'] == 'applied' else policy['active_via']
        if via is None:
            del inventory['policies'][source]
        else:
            policy.update(active_via=via, desired_via=via, revision=policy['revision'] + 1)
        (directory / 'inventory.json').write_text(json.dumps(inventory))
        if (directory / 'lose-ack').exists():
            return self.reply(503, {'error': 'injected lost acknowledgement'})
        self.reply(200, self.status(inventory, source))


def dns_answer(data):
    pos = 12
    while data[pos]:
        pos += data[pos] + 1
    pos += 1
    kind, cls = struct.unpack('!HH', data[pos:pos + 4])
    question = data[12:pos + 4]
    value = {1: '192.0.2.1', 28: '2001:db8:ffff::1'}.get(kind)
    answer = b''
    if value:
        address = ipaddress.ip_address(value).packed
        answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, cls, 30, len(address)) + address
    return data[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0) + question + answer

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(dns_answer(data), self.client_address)

class TCP(socketserver.StreamRequestHandler):
    def handle(self):
        length = struct.unpack('!H', self.rfile.read(2))[0]
        answer = dns_answer(self.rfile.read(length))
        self.wfile.write(struct.pack('!H', len(answer)) + answer)

servers = []
if a.mode == 'api':
    servers.append(http.server.ThreadingHTTPServer(('127.0.0.1', 18080), Handler))
elif a.mode == 'internet':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')
    for cls, bind in [(http.server.ThreadingHTTPServer, '0.0.0.0'), (HTTP6, '::')]:
        server = cls((bind, 443), Handler, bind_and_activate=False)
        if cls is HTTP6:
            server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.server_bind()
        server.server_activate()
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
else:
    for bind in [a.ipv4, a.ipv6]:
        for base, handler in [(socketserver.ThreadingUDPServer, UDP), (socketserver.ThreadingTCPServer, TCP)]:
            cls = type('DNS', (base,), {'address_family': socket.AF_INET6 if ':' in bind else socket.AF_INET,
                                      'allow_reuse_address': True})
            servers.append(cls((bind, 53), handler))
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
(directory / ('ready-' + a.mode + (('-' + a.ipv4) if a.ipv4 else ''))).touch()
threading.Event().wait()
