// Failure cases: an HTTP/2 idle socket error must not kill the process after a completed fetch;
// direct requests, proxy destinations, HTTPS proxies and DNS-over-HTTPS must all negotiate HTTP/1.1.
// Routing to a checked IP must keep the original Host, SNI and certificate validation intact.
import "./setup.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);
const directory = await mkdtemp(path.join(os.tmpdir(), "outbound-protocol-"));
const cert = path.join(directory, "cert.pem");
const key = path.join(directory, "key.pem");
// A checked-in self-signed pair instead of the openssl CLI, which Windows does not have.
// The key is test-only, scoped to the hosts below and valid for a century.
const CERT = `-----BEGIN CERTIFICATE-----
MIIDFjCCAf6gAwIBAgIUR2F/3KLgKptMK3OqwskSxKkjh5MwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQb3V0Ym91bmQuaW52YWxpZDAgFw0yNjEwMDgxMjA1MDFa
GA8yMTI2MDkxNDEyMDUwMVowGzEZMBcGA1UEAwwQb3V0Ym91bmQuaW52YWxpZDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOg2ZRYdVO6efIDePmyAIuvO
pvVUDeL7bQKsXCxltr+53wbltpfTxwNvPHsDTseVe2WvWsGtFyXf0/KmGSabk2iF
DpD3vfjSURQpJuyS4LnBZA1TsfAqhhzYb8uOEXCAj3oqfXouuuQEzJOWux+aD+ah
XfPo5gltQlWmnX/i2FuBxvefdWm4kTDF5Lgko2GSpkzSBOw73o7+pqAwPvbAGVYf
fLlxyfQhCce5IhtqiJFksqmPsyS0GzH4dwvXTKXKgEEIcu8Pj3acaHuuVXAvm50V
3U6CCo04E6nYE5JO/IXwN1+piFtQ348Egq985RFs7UcYOSdExuHnDA9m5q4c7o8C
AwEAAaNQME4wDwYDVR0TAQH/BAUwAwEB/zA7BgNVHREENDAyghBvdXRib3VuZC5p
bnZhbGlkghJjbG91ZGZsYXJlLWRucy5jb22HBH8AAAGHBF242CIwDQYJKoZIhvcN
AQELBQADggEBAKymXX7Cjq+fP+bfGrvUkFNYs1/KePVDfOO1mvVOBQPDypVUpUsJ
n11amm3Ap74lxzoAF2TiHgjHyJJYUHGQQbneuTrQtWqxK5cEGhDCk5+l3V24npRb
lKJsZj/A5UyPBlJpExI95Vfh0q1QZZvC5LT5k/t+7o+do8GP8e5sVUkM5+MjgcEC
D1oYdywLHXTTWh14IgU3DqnzGtxDOvPcvl60HBYVvOvCML/gl2W2WWDqKyBhtFrS
esfm9C+0ZA+n9sB53V1eSRV7VVre6KjqJAT1xh3wmTpBT2Ab9BJrWDFLolX3Q87F
/q3a92u1fFb+gONPq+r2EQ/fHhlTgfP5s4M=
-----END CERTIFICATE-----`;
const KEY = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDoNmUWHVTunnyA
3j5sgCLrzqb1VA3i+20CrFwsZba/ud8G5baX08cDbzx7A07HlXtlr1rBrRcl39Py
phkmm5NohQ6Q97340lEUKSbskuC5wWQNU7HwKoYc2G/LjhFwgI96Kn16LrrkBMyT
lrsfmg/moV3z6OYJbUJVpp1/4thbgcb3n3VpuJEwxeS4JKNhkqZM0gTsO96O/qag
MD72wBlWH3y5ccn0IQnHuSIbaoiRZLKpj7MktBsx+HcL10ylyoBBCHLvD492nGh7
rlVwL5udFd1OggqNOBOp2BOSTvyF8DdfqYhbUN+PBIKvfOURbO1HGDknRMbh5wwP
ZuauHO6PAgMBAAECggEBALr/UthENqkSJ+D/F/X4Gica+4iEb8ph/p8wfemi30/2
NowvYKNTf+hcI7BMMZy32+8/Dy74XLO7U8sLxyU4E7UPsXM8jldZxsEdgqLwhNgR
zKiOxbRKCkYgZabeeVzHqsMOhI1oJEiLNNOFhpskTbnEKQzKeLUOr2SaECt0WhcV
GiiN7Q7uEcF2yh7vWqRyLJv+C7xlPTedU9sqmCrBsOPBLe9sJsDees/F6BDSv7XH
R7j4k2lOhxoxSIoRyDJ2Xil+rQHVnbIVhNdUo+uSNhBGDf745IbLGwsaMsVNO1qQ
WxG2fZdqDiMq+EUtxhsluLJ2EXWfD1AlDnRhBpG1csECgYEA/9LAlW+S+W4zEvxr
8TrG33TT9lro2Ma/ASfZ84tnDmQLC+vhdqeOONeCheR0SdZHZu3K6ufYdBhu5TGV
1cvSq1HK3fJFoqoeRihQUhr9Ga/X/prclXAZ4hHk9a80n3m+2SuH7otZIKeh6Lt8
4Aff8Tv4ODxhrnA/bqjCJ0TjzQsCgYEA6F93blS+GF0iHFQahFe01mnjZhngTj9U
laKQpFXrDNwHPRKC1HVVLNaZI2Fmx0j0GLP3ooxmYWbMG6J7HkbTFHW3jhPdhijf
gJl7S6BfZcfaG/11tbAJlD7xdVtwWnLasByvZknvahalGOyPFGZa3jN9HiizprV3
MT418ZLDrw0CgYBiQzxv6eRlZJu/ni+EABSlfkVwaijoIyb4tar07kXOdET99kOr
BN8PHFBpR4AXYHQaqBn6MsWkikIGTQ6FiX3JCmjG6akvuvJX9mIrt2wicrWfeTJj
QCTg/giZCgxHeUcCOcNDsEiyz1DUiTeFAeFV0rgcOa03iKwEwFObK83oUwKBgQDQ
Gzd1qxU38qiq4DODVJ0S7XAHL6Nv0E3rWNTbKEtCkAc3jc13gsFOT76ELiYC0fYx
7XMYs065anvfP+utWNaPW0GRT380OIS5wjrmpvDo0Uwnhx4VIlvh1WEfrk1346aw
1G/NVufAhhlDshANwAEfQNOL3/3MjnX5tvJOsBbqPQKBgQCHkoOJjvbBo5fZ+wH0
pa2QhSDWhXZ8PLSdomSpbHq/RBFWilLZQIZ+qnSytn3bXZgcYUpR83BjAY189k6j
Bg5P9Eu4RpJgzDCsR+BW/bqXYOBrw78oyzusTRYr9JTjKPQuNGASGhQlI32XZbZu
FL0qmNPmHj5fV7JlI5nbjA7wug==
-----END PRIVATE KEY-----`;
await writeFile(cert, CERT);
await writeFile(key, KEY);
after(() => rm(directory, { recursive: true, force: true }));

for (const route of ["direct", "proxy", "secure-proxy", "dns"] as const) {
  test(`outbound ${route} negotiates HTTP/1.1 and retains TLS identity`, async () => {
    const { stdout } = await exec(process.execPath, ["--input-type=module", "-e", `
      import { readFileSync } from 'node:fs';
      import { createServer } from 'node:http';
      import { createSecureServer } from 'node:http2';
      import net from 'node:net';
      import tls from 'node:tls';
      import { createRequire } from 'node:module';
      import { guardedFetch } from '@aihot/backend/lib/http-fetch';
      import { createEgressProxy, createEgressResolver } from '@aihot/backend/lib/egress-proxy';
      const { fetch } = createRequire(new URL('./packages/backend/package.json', import.meta.url))('undici');
      const route = process.env.TEST_OUTBOUND_ROUTE;
      const options = { key: readFileSync(process.env.TEST_TLS_KEY), cert: readFileSync(process.env.NODE_EXTRA_CA_CERTS), allowHTTP1: true };
      const requests = [], tunnels = [], proxyProtocols = [], sockets = new Set();
      const origin = createSecureServer(options, (req, res) => {
        requests.push({ version: req.httpVersion, host: req.headers.host ?? req.headers[':authority'], sni: req.socket.servername });
        if (req.url.startsWith('/dns-query')) {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: '93.184.216.34', TTL: 60 }] }));
        } else res.end('ok');
      });
      const proxy = route === 'secure-proxy' ? createSecureServer(options) : createServer();
      function tunnel(req, socket, head) {
        tunnels.push(req.url);
        const upstream = net.connect(origin.address().port, '127.0.0.1', () => {
          socket.write('HTTP/1.1 200 Connection Established\\r\\n\\r\\n');
          upstream.write(head);
          socket.pipe(upstream).pipe(socket);
        });
        sockets.add(upstream);
        socket.on('error', () => upstream.destroy());
        upstream.on('error', () => socket.destroy());
        socket.on('close', () => upstream.destroy());
      }
      proxy.on('connect', tunnel);
      if (route === 'secure-proxy') {
        proxy.on('secureConnection', socket => proxyProtocols.push(socket.alpnProtocol));
        proxy.on('stream', stream => { stream.respond({ ':status': 503 }); stream.end(); });
      }
      for (const server of [origin, proxy]) {
        server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      }
      // Only the direct public IP is redirected to the local fixture. Certificate checks remain on;
      // the proxy paths exercise their real CONNECT and TLS implementation without interception.
      const connect = tls.connect;
      tls.connect = function(options, ...rest) {
        if (options.host === '93.184.216.34') options = { ...options, host: '127.0.0.1', port: origin.address().port };
        return connect.call(this, options, ...rest);
      };
      const proxyUrl = (route === 'secure-proxy' ? 'https' : 'http') + '://127.0.0.1:' + proxy.address().port;
      let error = null, agent;
      try {
        if (route === 'direct') {
          const result = await guardedFetch('https://93.184.216.34/item', { route: 'direct' });
          if (result.text() !== 'ok') throw new Error('response lost');
        } else if (route === 'dns') {
          await createEgressResolver(proxyUrl)('outbound.invalid');
        } else {
          agent = createEgressProxy(proxyUrl, async () => ['93.184.216.34']);
          const response = await fetch('https://outbound.invalid/item', { dispatcher: agent, signal: AbortSignal.timeout(2000) });
          if (await response.text() !== 'ok') throw new Error('response lost');
        }
      } catch (failure) { error = String(failure); }
      finally {
        await agent?.destroy();
        for (const socket of sockets) socket.destroy();
        await Promise.all([origin, proxy].map(server => new Promise(resolve => server.close(resolve))));
      }
      console.log(JSON.stringify({ requests, tunnels, proxyProtocols: [...new Set(proxyProtocols)], error }));
    `], {
      cwd: new URL("../", import.meta.url), timeout: 10000,
      env: { ...process.env, EGRESS_PROXY_URL: "", ALLOW_PRIVATE_NETWORK_FETCH: "false", NODE_EXTRA_CA_CERTS: cert,
        TEST_TLS_KEY: key, TEST_OUTBOUND_ROUTE: route },
    });
    const result = JSON.parse(stdout) as { requests: Array<{ version: string; host: string; sni: string }>; tunnels: string[]; proxyProtocols: string[]; error: string | null };
    assert.equal(result.error, null, JSON.stringify(result));
    assert.ok(result.requests.length > 0);
    assert.ok(result.requests.every(request => request.version === "1.1"), JSON.stringify(result));
    if (route === "proxy" || route === "secure-proxy") {
      assert.deepEqual(result.tunnels, ["93.184.216.34:443"]);
      assert.equal(result.requests[0]!.host, "outbound.invalid");
      assert.equal(result.requests[0]!.sni, "outbound.invalid");
    }
    if (route === "secure-proxy") assert.deepEqual(result.proxyProtocols, ["http/1.1"]);
    if (route === "dns") {
      assert.ok(result.requests.every(request => request.host === "cloudflare-dns.com" && request.sni === "cloudflare-dns.com"));
    }
  });
}
