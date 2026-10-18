#!/usr/bin/env python3
"""Real TLS/QUIC HTTP/3 security suite; requires the isolated nginx test fixture.

No TCP transport or protocol fallback. Trust the fixture certificate explicitly:
python http3-test.py https://localhost:8443 --ca-file /path/to/cert.pem
"""
import argparse
import asyncio
import base64
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
import hashlib
import html
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, StreamReset
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def encoded(body):
    return json.dumps(body, separators=(',', ':')).encode()


@dataclass
class Response:
    headers: list = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)

    def header(self, name):
        return next((v.decode() for k, v in self.headers if k == name.encode()), None)

    @property
    def status(self):
        return int(self.header(':status'))

    @property
    def admitted(self):
        return b'upstream-content' in self.body


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}
        self.alpn = None

    def fail(self, stream_id, error):
        pending = self.pending.pop(stream_id, None)
        if pending and not pending[0].done():
            pending[0].set_exception(error)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.alpn = event.alpn_protocol
        if isinstance(event, ConnectionTerminated):
            for stream_id in list(self.pending):
                self.fail(stream_id, ConnectionError(f'QUIC closed: {event}'))
        elif isinstance(event, StreamReset):
            self.fail(event.stream_id, ConnectionError(f'QUIC stream reset: {event}'))
        for http_event in self.http.handle_event(event):
            if not isinstance(http_event, (HeadersReceived, DataReceived)):
                continue
            pending = self.pending.get(http_event.stream_id)
            if pending is None:
                continue
            waiter, response = pending
            if isinstance(http_event, HeadersReceived):
                response.headers.extend(http_event.headers)
            else:
                response.body.extend(http_event.data)
                if len(response.body) > 256 * 1024:
                    self.fail(http_event.stream_id, ValueError('fixture response too large'))
                    continue
            if http_event.stream_ended:
                self.pending.pop(http_event.stream_id)
                if not waiter.done():
                    waiter.set_result(response)

    async def request(self, authority, method, path, body=None, headers=None, finish=True):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = asyncio.get_running_loop().create_future()
        self.pending[stream_id] = waiter, Response()
        outgoing = {'user-agent': 'h3-security-test', **(headers or {})}
        if body is not None:
            outgoing.setdefault('content-type', 'application/json')
        self.http.send_headers(stream_id, [
            (b':method', method.encode()), (b':scheme', b'https'),
            (b':authority', authority.encode()), (b':path', path.encode()),
            *[(k.encode(), v.encode()) for k, v in outgoing.items()],
        ], end_stream=body is None)
        # Deliberately omit Content-Length and send multiple HTTP/3 DATA frames.
        if body is not None:
            for offset in range(0, len(body), 1024):
                last = offset + 1024 >= len(body)
                self.http.send_data(stream_id, body[offset:offset + 1024], end_stream=last and finish)
        self.transmit()
        try:
            response = await asyncio.wait_for(waiter, timeout=10)
            assert self.alpn == 'h3', f'wrong ALPN: {self.alpn}'
            assert response.header('x-pow-test-http3') == 'h3', 'server did not confirm HTTP/3'
            return response
        finally:
            self.pending.pop(stream_id, None)


async def suite(url, ca_file):
    parsed = urlsplit(url)
    assert parsed.scheme == 'https' and parsed.hostname, 'HTTP/3 requires an https URL'
    configuration = QuicConfiguration(is_client=True, alpn_protocols=['h3'], idle_timeout=10)
    configuration.load_verify_locations(cafile=str(ca_file))
    key = ec.generate_private_key(ec.SECP256R1())
    pubkey = b64(key.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint))

    def sign(message, private_key=key):
        r, s = decode_dss_signature(private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

    def solve(challenge, start=0):
        target = (1 << 256) // challenge['difficulty']
        nonce = start
        while int.from_bytes(hashlib.sha256((challenge['salt'] + str(nonce)).encode()).digest(), 'big') >= target:
            nonce += 1
        return nonce

    async with AsyncExitStack() as stack:
        async def connection():
            return await stack.enter_async_context(connect(parsed.hostname, parsed.port or 443,
                                                         configuration=configuration, create_protocol=Client))
        client = await connection()

        async def send(method, path, body=None, headers=None, via=None, finish=True):
            return await (via or client).request(parsed.netloc, method, path,
                                                None if body is None else encoded(body), headers, finish)

        async def submission():
            response = await send('GET', '/.pow/challenge', headers={'x-pow-key': pubkey})
            assert response.status == 200 and response.header('cache-control') == 'no-store'
            challenge = json.loads(response.body)
            return {**challenge, 'nonce': solve(challenge), 'pubkey': pubkey,
                    'signature': sign('pow-gate-redeem-v2 ' + challenge['token'])}

        def winner(responses):
            assert [r.status for r in responses].count(204) == 1, [r.status for r in responses]
            assert [r.status for r in responses].count(409) == 15, [r.status for r in responses]
            return next(r for r in responses if r.status == 204)

        assert (await send('GET', '/healthz')).status == 200
        assert not (await send('GET', '/')).admitted
        assert (await send('GET', '/.pow/challenge')).status == 400
        assert (await send('GET', '/.pow/challenge', headers={'x-pow-key': 'A' * 87})).status == 400
        assert (await send('GET', '/.pow/verify')).status == 405
        body = await submission()
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_pubkey = b64(other_key.public_key().public_bytes(serialization.Encoding.X962,
                                                              serialization.PublicFormat.UncompressedPoint))
        substituted = {**body, 'pubkey': other_pubkey,
                       'signature': sign('pow-gate-redeem-v2 ' + body['token'], other_key)}
        assert (await send('POST', '/.pow/verify', substituted)).status == 400
        for invalid in [{**body, 'signature': b64(bytes(64))}, {**body, 'difficulty': 1}]:
            assert (await send('POST', '/.pow/verify', invalid)).status == 400
        assert (await send('POST', '/.pow/verify', body, {'user-agent': 'other-client'})).status == 400
        assert (await send('POST', '/.pow/verify', body, {'x-pow-test-ip': '192.0.2.9'})).status == 400

        # Sixteen simultaneous streams on ONE QUIC connection.
        responses = await asyncio.gather(*(send('POST', '/.pow/verify', body) for _ in range(16)))
        cookie = winner(responses).header('set-cookie').split(';')[0]
        assert (await send('GET', '/', headers={'cookie': cookie})).admitted
        for path, extra in [('/', {'user-agent': 'other-client'}),
                            ('/', {'x-pow-test-ip': '192.0.2.9'}),
                            ('/other-policy', {}), ('/stronger', {})]:
            assert not (await send('GET', path, headers={'cookie': cookie, **extra})).admitted
        assert not (await send('GET', '/', headers={'cookie': cookie, 'sec-fetch-dest': 'empty'})).admitted
        ts = int(time.time())
        proof = f'{sign(f"GET / {ts}")}.{ts}'
        assert (await send('GET', '/', headers={'cookie': cookie, 'sec-fetch-dest': 'empty',
                                               'x-pow-proof': proof})).admitted
        assert (await send('POST', '/.pow/verify', {**body, 'nonce': solve(body, body['nonce'] + 1)})).status == 409

        # Independent UDP source ports distribute traffic across reuseport
        # workers, testing the same shared ledger beyond one worker's streams.
        peers = await asyncio.gather(*(connection() for _ in range(16)))
        fresh = await submission()
        responses = await asyncio.gather(*(send('POST', '/.pow/verify', fresh, via=peer) for peer in peers))
        winner(responses)
        workers = {r.header('x-pow-test-worker') for r in responses}
        assert None not in workers and len(workers) >= 2, f'race did not exercise multiple workers: {workers}'

        exact = {**await submission(), 'padding': ''}
        exact['padding'] = 'x' * (8192 - len(encoded(exact)))
        assert len(encoded(exact)) == 8192
        assert (await send('POST', '/.pow/verify', exact)).status == 204
        over = {**await submission(), 'padding': ''}
        over['padding'] = 'x' * (8193 - len(encoded(over)))
        assert len(encoded(over)) == 8193
        # Require 413 BEFORE FIN: the filter must reject while streaming.
        assert (await send('POST', '/.pow/verify', over, finish=False)).status == 413
        del over['padding']
        assert (await send('POST', '/.pow/verify', over)).status == 204

        # No-JS grants use the same one-use state over HTTP/3.
        nojs_headers = {'user-agent': 'nojsbot'}
        page = await send('GET', '/', headers=nojs_headers)
        grant = html.unescape(re.search(rb'(/\.pow/pass\?t=[^"\s<>]+)', page.body).group(1).decode())
        await asyncio.sleep(2.1)
        redeemed = await send('GET', grant, headers=nojs_headers)
        assert redeemed.status == 302 and redeemed.header('set-cookie')
        assert (await send('GET', grant, headers=nojs_headers)).status == 409
        print(f'PASS: HTTP/3 TLS/ALPN, multiplexed and cross-worker races ({len(workers)} workers), '
              'key/context/policy binding, proofs, nonce reuse, streaming 8192/8193-byte boundary before FIN, no-JS reuse')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--ca-file', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(asyncio.wait_for(suite(args.url, args.ca_file), timeout=60))
