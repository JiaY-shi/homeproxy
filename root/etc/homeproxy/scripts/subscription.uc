/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026
 */

'use strict';

import { mkstemp } from 'fs';
import { decodeBase64Str, executeCommand, parseURL, validation } from 'homeproxy';

function scalar(value) {
	return (value === null || type(value) in ['array', 'object']) ? null : `${value}`;
}

function flag(value) {
	return value in [true, 1, '1', 'true'] ? '1' : '0';
}

function list(value) {
	return value === null ? null : map(type(value) === 'array' ? value : [value], scalar);
}

/* Only use provider DNS for resolving its node addresses. */
export function parseClashDNS(address) {
	if (type(address) !== 'string')
		return null;
	if (validation('ipaddr', address))
		return { type: 'udp', server: replace(address, /\[|\]/g, '') };

	const url = parseURL(address);
	/* sing-box exposes a DoH path field without a URL query field. */
	if (!url || url.search || !(url.protocol in ['https', 'tls', 'tcp', 'udp']))
		return null;
	const ports = { https: 443, tls: 853, tcp: 53, udp: 53 };
	const server = replace(url.hostname, /\[|\]/g, '');
	const config = {
		type: url.protocol,
		server,
		server_port: int(url.port || ports[url.protocol]),
		path: url.protocol === 'https' ? url.pathname : null,
		domain_resolver: validation('ipaddr', server) ? null : 'default-dns'
	};
	if (!validation('port', config.server_port))
		return null;
	if (url.protocol in ['https', 'tls'])
		config.tls = {
			enabled: true,
			insecure: !!match(url.hash || '', /(^|&)skip-cert-verify=(true|1)(&|$)/)
		};
	return config;
}

function policy_resolver(host, policies) {
	if (type(host) !== 'string' || type(policies) !== 'object')
		return null;
	host = lc(host);
	let selected, specificity = -1;
	for (let pattern, servers in policies) {
		pattern = lc(pattern);
		const suffix = match(pattern, /^(\+\.|\*\.|\.)/);
		const domain = suffix ? substr(pattern, length(suffix[0])) : pattern;
		if (host !== domain && (!suffix || length(host) <= length(domain) ||
		    substr(host, length(host) - length(domain) - 1) !== '.' + domain))
			continue;
		if (suffix?.[0] === '*.' && host === domain)
			continue;
		const score = length(domain) + (suffix ? 0 : 1);
		if (score <= specificity)
			continue;
		for (let server in list(servers))
			if (parseClashDNS(server)) {
				selected = server;
				specificity = score;
				break;
			}
	}
	return selected;
}

function mark_nodes(nodes, format, policies) {
	if (type(nodes) !== 'array')
		die('Subscription must contain a node array');

	for (let node in nodes)
		if (type(node) === 'object') {
			node.nodetype = format;
			if (format === 'clash')
				node._clash_dns_server = policy_resolver(node.server, policies);
		}

	return nodes;
}

export function parseSubscription(content) {
	content = trim(replace(content, /^\xEF\xBB\xBF/, ''));
	let data;
	try {
		data = json(content);
	} catch (e) {}

	if (type(data) === 'object') {
		if ('proxies' in data)
			return mark_nodes(data.proxies, 'clash', data.dns?.['nameserver-policy']);
		if ('servers' in data)
			return mark_nodes(data.servers, 'sip008');
	} else if (type(data) === 'array')
		return mark_nodes(data, 'sip008');

	const uri_pattern = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
	if (match(content, uri_pattern))
		return split(content, /\r?\n/);

	const decoded = decodeBase64Str(content);
	if (decoded && match(trim(decoded), uri_pattern))
		return split(trim(decoded), /\r?\n/);

	/* Feed YAML through an anonymous file, without putting credentials in argv. */
	const input = mkstemp();
	if (!input)
		die('Unable to create subscription input');
	input.write(content);
	input.seek(0);
	const output = executeCommand(`/usr/bin/yq eval --yaml-fix-merge-anchor-to-spec=true --input-format=yaml --output-format=json --indent=0 '{"proxies": .proxies, "nameserver-policy": .dns."nameserver-policy"} | explode(.)' - <&${input.fileno()}`);
	input.close();

	if (output.exitcode !== 0)
		die('Unable to parse Clash YAML subscription');

	data = json(output.stdout);
	return mark_nodes(data.proxies, 'clash', data['nameserver-policy']);
}

function hopping_ports(value) {
	if (value === null)
		return null;

	let ports = [];
	for (let item in list(value))
		for (let port in split(item, ',')) {
			port = replace(trim(port), /-/g, ':');
			const range = match(port, /^([0-9]+)(:([0-9]+))?$/);
			if (!range || int(range[1]) < 1 || int(range[1]) > 65535 ||
			    (range[3] && (int(range[3]) < int(range[1]) || int(range[3]) > 65535)))
				return null;
			push(ports, port);
		}

	return length(ports) ? ports : null;
}

function mbps(value) {
	if (value === null)
		return null;
	const rate = match(scalar(value), /^([0-9]+(\.[0-9]+)?)\s*(([kKmMgGtT]?)([bB])(ps|\/s))?$/);
	if (!rate)
		return null;

	const units = { k: 0.001, m: 1, g: 1000, t: 1000000 };
	const number = rate[1] * (rate[5] ? (units[lc(rate[4])] || 0.000001) : 1) * (rate[5] === 'B' ? 8 : 1);
	return scalar(int(number + 0.5));
}

/* Map Clash/Mihomo node fields to the existing HomeProxy UCI schema. */
export function parseClash(node, features) {
	const protocols = {
		ss: 'shadowsocks', socks5: 'socks', http: 'http',
		vmess: 'vmess', vless: 'vless', trojan: 'trojan',
		hysteria: 'hysteria', hysteria2: 'hysteria2', tuic: 'tuic', anytls: 'anytls'
	};
	if (type(node) !== 'object' || !protocols[node.type])
		return null;
	features ||= {};
	if (node.type in ['hysteria', 'hysteria2', 'tuic'] && !features.with_quic)
		return null;

	/* These wrappers require separate outbounds, which cannot be flattened. */
	if (node['shadow-tls-opts'] || node['restls-opts'] || node['jls-opts'] || node['dialer-proxy'])
		return null;

	const config = {
		label: scalar(node.name),
		type: protocols[node.type],
		address: scalar(node.server),
		port: scalar(node.port),
		username: scalar(node.username),
		password: scalar(node.password),
		clash_dns_server: scalar(node._clash_dns_server),
		tcp_fast_open: node.tfo !== null ? flag(node.tfo) : null
	};

	switch (node.type) {
	case 'anytls':
		config.anytls_idle_session_check_interval = scalar(node['idle-session-check-interval']);
		config.anytls_idle_session_timeout = scalar(node['idle-session-timeout']);
		config.anytls_min_idle_session = scalar(node['min-idle-session']);
		break;
	case 'http':
		break;
	case 'socks5':
		if (flag(node.tls) === '1')
			return null;
		config.socks_version = '5';
		break;
	case 'ss':
		config.shadowsocks_encrypt_method = scalar(node.cipher);
		if (node.plugin) {
			const opts = node['plugin-opts'] || {};
			let plugin_opts = [];
			switch (node.plugin) {
			case 'obfs':
				config.shadowsocks_plugin = 'obfs-local';
				push(plugin_opts, `obfs=${opts.mode || 'http'}`);
				if (opts.host)
					push(plugin_opts, `obfs-host=${opts.host}`);
				break;
			case 'v2ray-plugin':
				config.shadowsocks_plugin = 'v2ray-plugin';
				for (let key, value in opts)
					if (value === true)
						push(plugin_opts, key);
					else if (value !== false && value !== null)
						push(plugin_opts, `${key}=${value}`);
				break;
			default:
				return null;
			}
			config.shadowsocks_plugin_opts = join(';', plugin_opts);
		}
		if (node['udp-over-tcp'] !== null) {
			config.udp_over_tcp = flag(node['udp-over-tcp']);
			config.udp_over_tcp_version = scalar(node['udp-over-tcp-version'] ?? 2);
		}
		break;
	case 'vmess':
		config.uuid = scalar(node.uuid);
		config.vmess_alterid = scalar(node.alterId ?? 0);
		config.vmess_encrypt = scalar(node.cipher || 'auto');
		config.vmess_global_padding = '1';
		break;
	case 'vless':
		config.uuid = scalar(node.uuid);
		config.vless_flow = scalar(node.flow);
		break;
	case 'trojan':
		break;
	case 'hysteria':
		if (node.protocol && node.protocol !== 'udp')
			return null;
		config.hysteria_protocol = 'udp';
		config.hysteria_auth_type = node['auth-str'] !== null ? 'string' : 'base64';
		config.hysteria_auth_payload = scalar(node['auth-str'] ?? node.auth);
		config.hysteria_obfs_password = scalar(node.obfs);
		config.hysteria_recv_window_conn = scalar(node['recv-window-conn']);
		config.hysteria_revc_window = scalar(node['recv-window']);
		config.hysteria_disable_mtu_discovery = flag(node['disable-mtu-discovery']);
		/* fall through */
	case 'hysteria2':
		config.hysteria_up_mbps = mbps(node.up);
		config.hysteria_down_mbps = mbps(node.down);
		if (node.ports !== null) {
			config.hysteria_hopping_port = hopping_ports(node.ports);
			if (!config.hysteria_hopping_port)
				return null;
			config.port ||= split(config.hysteria_hopping_port[0], ':')[0];
		}
		config.hysteria_hop_interval = scalar(node['hop-interval']);
		if (node.type === 'hysteria2') {
			if (node.obfs && node.obfs !== 'salamander')
				return null;
			config.hysteria_obfs_type = scalar(node.obfs);
			config.hysteria_obfs_password = scalar(node['obfs-password']);
		}
		break;
	case 'tuic':
		if (node.token)
			return null;
		config.uuid = scalar(node.uuid);
		config.tuic_congestion_control = scalar(node['congestion-controller']);
		config.tuic_udp_relay_mode = scalar(node['udp-relay-mode']);
		config.tuic_enable_zero_rtt = flag(node['reduce-rtt']);
		break;
	}

	config.tls = (node.type in ['anytls', 'hysteria', 'hysteria2', 'trojan', 'tuic']) ? '1' : flag(node.tls);
	if (config.tls === '1') {
		config.tls_sni = scalar(node.sni || node.servername);
		config.tls_insecure = flag(node['skip-cert-verify']);
		config.tls_alpn = list(node.alpn);
		if (features.with_utls && !(node.type in ['hysteria', 'hysteria2', 'tuic']))
			config.tls_utls = scalar(node['client-fingerprint']);
		const reality = node['reality-opts'];
		if (type(reality) === 'object') {
			config.tls_reality = '1';
			config.tls_reality_public_key = scalar(reality['public-key']);
			config.tls_reality_short_id = scalar(reality['short-id']);
		}
	}

	if (node.type in ['vmess', 'vless', 'trojan']) {
		const network = node.network || 'tcp';
		switch (network) {
		case 'tcp':
			break;
		case 'ws':
			const ws = node['ws-opts'] || {};
			config.transport = 'ws';
			config.ws_host = scalar(ws.headers?.Host || ws.headers?.host);
			config.ws_path = scalar(ws.path);
			config.websocket_early_data = scalar(ws['max-early-data']);
			config.websocket_early_data_header = scalar(ws['early-data-header-name']);
			if (config.ws_path && match(config.ws_path, /\?ed=/)) {
				config.websocket_early_data ||= split(config.ws_path, '?ed=')[1];
				config.websocket_early_data_header ||= 'Sec-WebSocket-Protocol';
				config.ws_path = split(config.ws_path, '?ed=')[0];
			}
			break;
		case 'h2':
		case 'http':
			const http = node[network === 'h2' ? 'h2-opts' : 'http-opts'] || {};
			config.transport = 'http';
			config.http_host = list(http.host || http.headers?.Host || http.headers?.host);
			config.http_path = scalar(type(http.path) === 'array' ? http.path[0] : http.path);
			config.http_method = scalar(http.method);
			break;
		case 'grpc':
			config.transport = 'grpc';
			config.grpc_servicename = scalar(node['grpc-opts']?.['grpc-service-name']);
			break;
		default:
			return null;
		}
	}

	const smux = node.smux;
	if (type(smux) === 'object' && flag(smux.enabled) === '1') {
		config.multiplex = '1';
		config.multiplex_protocol = scalar(smux.protocol);
		config.multiplex_max_connections = scalar(smux['max-connections']);
		config.multiplex_min_streams = scalar(smux['min-streams']);
		config.multiplex_max_streams = scalar(smux['max-streams']);
		config.multiplex_padding = flag(smux.padding);
	}

	return config;
}
