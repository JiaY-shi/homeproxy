/* SPDX-License-Identifier: GPL-2.0-only */

'use strict';

import { readfile, unlink, writefile } from 'fs';
import { cursor } from 'uci';

/* Validate installed subscription nodes with the actual sing-box parser. */
const nodes = [];
cursor().foreach('homeproxy', 'node', node => {
	if (node.grouphash)
		push(nodes, node['.name']);
});
if (!length(nodes))
	die('No installed subscription nodes\n');

let combined;
const dns_tags = {};
for (let offset = 0; offset < length(nodes); offset += 3) {
	const id = `${7000 + offset}`;
	const path = `/var/run/homeproxy/node-test-${id}.json`;
	const batch = slice(nodes, offset, offset + 3);
	if (system([ '/etc/homeproxy/scripts/generate_client.uc', 'latency-test', id, ...batch ]) !== 0 ||
	    system([ '/usr/bin/sing-box', 'check', '-c', path ]) !== 0)
		die(`Invalid generated node configuration in batch ${offset}\n`);

	const config = json(readfile(path));
	if (!combined) {
		combined = { ...config };
		combined.outbounds = filter(config.outbounds, outbound => outbound.tag === 'direct-out');
		combined.dns = { ...config.dns, servers: [] };
	}
	for (let server in config.dns.servers)
		if (!dns_tags[server.tag]) {
			push(combined.dns.servers, server);
			dns_tags[server.tag] = true;
		}
	for (let outbound in config.outbounds)
		if (outbound.type !== 'selector' && outbound.tag !== 'direct-out')
			push(combined.outbounds, outbound);
	unlink(path);
}

push(combined.outbounds, {
	type: 'selector',
	tag: 'latency-test',
	outbounds: map(nodes, node => 'latency-' + node)
});
combined.log.level = 'debug';
combined.log.output = '/var/run/homeproxy/clash-all-nodes.log';
const path = '/var/run/homeproxy/clash-all-nodes.json';
writefile(path, sprintf('%.J\n', combined));
if (system([ '/usr/bin/sing-box', 'check', '-c', path ]) !== 0)
	die('Invalid combined test configuration\n');
printf('PASS: %d installed node configurations\n', length(nodes));
