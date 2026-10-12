/* SPDX-License-Identifier: GPL-2.0-only */

'use strict';

import { access, readfile } from 'fs';
import { parseClash, parseClashDNS, parseSubscription } from 'subscription';

let checks = 0;
function check(value, message) {
	if (!value)
		die(`FAIL: ${message}\n`);
	checks++;
}

function rejects(content) {
	try {
		parseSubscription(content);
	} catch (e) {
		return true;
	}
	return false;
}

const features = { with_quic: true, with_utls: true };
const nodes = parseSubscription(readfile(ARGV[0]));
check(length(nodes) === 12 && nodes[0].nodetype === 'clash', 'block and flow YAML');
check(nodes[0].port === 8443, 'explicit fields override YAML merge defaults');

const anytls = parseClash(nodes[0], features);
check(anytls.type === 'anytls' && anytls.password === '001234', 'AnyTLS credentials retain leading zeros');
check(anytls.label === '香港 #1: AnyTLS' && anytls.port === '8443', 'Unicode label and scalar port');
check(anytls.tls === '1' && anytls.tls_insecure === '0' && anytls.tcp_fast_open === '1', 'TLS and boolean conversion');
check(anytls.tls_sni === 'example.org' && anytls.tls_utls === 'chrome', 'SNI and client fingerprint');
check(anytls.anytls_min_idle_session === '0' && anytls.anytls_idle_session_check_interval === '30', 'AnyTLS session settings');
check(anytls.clash_dns_server === 'https://dns.example.org:8443/dns-query/test#skip-cert-verify=true', 'node DNS policy is retained');
const resolver = parseClashDNS(anytls.clash_dns_server);
check(resolver.type === 'https' && resolver.server_port === 8443 && resolver.path === '/dns-query/test', 'provider DoH address, port and path');
check(resolver.tls.insecure === true && resolver.domain_resolver === 'default-dns', 'provider DoH TLS and bootstrap resolver');
check(parseClashDNS('tls://1.1.1.1').server_port === 853 && parseClashDNS('1.1.1.1').type === 'udp', 'DoT and UDP provider resolvers');
check(parseClashDNS('ftp://example.com') === null, 'unsupported provider DNS transports');
check(parseClashDNS('https://dns.example.org/dns-query?token=test') === null, 'DNS URL queries cannot be represented by sing-box path');
check(parseClash(nodes[0], {}).tls_utls === null, 'fingerprint respects sing-box build features');

const hy2 = parseClash(nodes[1], features);
check(hy2.type === 'hysteria2' && hy2.port === '20000', 'Hysteria2 ports without a fixed port');
check(join(',', hy2.hysteria_hopping_port) === '20000:21000,443', 'Hysteria2 port range conversion');
check(hy2.hysteria_up_mbps === '1000' && hy2.hysteria_down_mbps === '80', 'bandwidth units');
check(hy2.tls_insecure === '1' && hy2.hysteria_hop_interval === '30', 'Hysteria2 TLS and hopping interval');
check(parseClash(nodes[1], {}) === null, 'QUIC protocols require QUIC support');
check(parseClash({ ...nodes[1], ports: '65536-65537' }, features) === null, 'invalid hopping ports are skipped');

const vless = parseClash(nodes[2], features);
check(vless.tls_reality === '1' && vless.tls_reality_short_id === '0123456789abcdef', 'Reality keys');
check(vless.transport === 'ws' && vless.ws_path === '/websocket' && vless.websocket_early_data === '2048', 'WebSocket early data');
check(vless.ws_host === 'example.org' && length(vless.tls_alpn) === 2, 'WebSocket Host and ALPN');
const vmess = parseClash(nodes[3], features);
check(vmess.type === 'vmess' && vmess.vmess_alterid === '0' && vmess.transport === 'http' && vmess.http_host[0] === 'example.org', 'VMess and HTTP/2');
const trojan = parseClash(nodes[4], features);
check(trojan.transport === 'grpc' && trojan.grpc_servicename === 'tunnel', 'Trojan and gRPC');
check(trojan.password === nodes[4].password && !access('/tmp/homeproxy-clash-injection'), 'subscription strings are treated as data');
const ss = parseClash(nodes[5], features);
check(ss.type === 'shadowsocks' && ss.shadowsocks_plugin === 'obfs-local' && ss.shadowsocks_plugin_opts === 'obfs=tls;obfs-host=example.org', 'Shadowsocks plugin conversion');
check(ss.password === '密码:# test' && ss.udp_over_tcp === '1' && ss.udp_over_tcp_version === '2', 'Shadowsocks password and UDP over TCP');
check(parseClash(nodes[6], features).password === '12345', 'numeric YAML passwords become UCI strings');
check(parseClash(nodes[7], features).socks_version === '5', 'SOCKS5');
check(parseClash(nodes[8], features).tuic_congestion_control === 'bbr', 'TUIC');
check(parseClash(nodes[9], features).hysteria_auth_type === 'string', 'Hysteria v1');
check(parseClash(nodes[10], features) === null && parseClash(nodes[11], features) === null, 'unsupported and malformed nodes are skipped');
check(parseClash({ ...nodes[2], network: 'kcp' }, features) === null, 'unsupported transport is skipped');

const uris = 'ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#name with spaces\r\nanytls://pass@example.com:443#test';
check(parseSubscription(uris)[0] === split(uris, '\r\n')[0], 'plain URI subscription');
check(length(parseSubscription(b64enc(uris))) === 2, 'base64 URI subscription');
const sip = { server: 'example.com', server_port: 8388, method: 'aes-128-gcm', password: 'pass' };
check(parseSubscription(sprintf('%J', { version: 1, servers: [sip] }))[0].nodetype === 'sip008', 'SIP008 object subscription');
check(parseSubscription(sprintf('%J', [sip]))[0].server_port === 8388, 'SIP008 array subscription');
check(parseSubscription(sprintf('%J', { proxies: nodes }))[0].nodetype === 'clash', 'Clash JSON subscription');
check(length(parseSubscription('proxies: []')) === 0, 'empty Clash subscription');
check(parseSubscription('\xEF\xBB\xBFproxies: [{name: test, type: http, server: example.com, port: 80}]')[0].name === 'test', 'UTF-8 BOM');
check(rejects('proxies: [invalid'), 'malformed YAML is rejected');
check(rejects('proxies: {name: invalid}'), 'invalid proxies schema is rejected');
check(rejects('<html>not a subscription</html>'), 'non-subscription response is rejected');
check(rejects('proxies: []\n---\nproxies: []'), 'multiple YAML documents are rejected');

const policy = { '+.example.com': 'https://1.1.1.1/dns-query', 'sub.example.com': 'tls://1.1.1.1' };
let data = { proxies: [{type:'http',server:'sub.example.com',port:80}], dns: {'nameserver-policy':policy} };
check(parseSubscription(sprintf('%J',data))[0]._clash_dns_server === 'tls://1.1.1.1', 'specific DNS policy takes priority');
data.proxies[0].server = 'other.example.com';
check(parseSubscription(sprintf('%J',data))[0]._clash_dns_server === 'https://1.1.1.1/dns-query', 'suffix DNS policy matches subdomains');
data.proxies[0].server = 'unrelated.test';
check(parseSubscription(sprintf('%J',data))[0]._clash_dns_server === null, 'provider DNS does not affect unrelated nodes');

printf('PASS: %d subscription checks\n', checks);
