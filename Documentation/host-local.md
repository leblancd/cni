# host-local IP address management plugin

host-local IPAM allocates IPv4 and IPv6 addresses out of a specified address range. Optionally,
it can include a DNS configuration from a `resolv.conf` file on the host.

## Overview

host-local IPAM plugin allocates IPv4 and/or IPv6 addresses out of a specified address range.
It stores the state locally on the host filesystem, therefore ensuring uniqueness of IP addresses on a single host.

## Example configurations

IPv4:
```json
{
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16",
		"rangeStart": "10.10.1.20",
		"rangeEnd": "10.10.3.50",
		"gateway": "10.10.0.254",
		"routes": [
			{ "dst": "0.0.0.0/0" },
			{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" }
		],
		"dataDir": "/var/my-orchestrator/container-ipam-state"
	}
}
```

IPv6:
```json
{
	"ipam": {
		"type": "host-local",
		"subnet": "3ffe:ffff:0:01ff::/64",
		"rangeStart": "3ffe:ffff:0:01ff::0010",
		"rangeEnd": "3ffe:ffff:0:01ff::0020",
		"routes": [
			{ "dst": "3ffe:ffff:0:01ff::1/64" }
		],
		"resolvConf": "/etc/resolv.conf"
	}
}
```

IPv4 + IPv6 (Dual Stack):
```json
{
	"ipam": {
		"type": "host-local",
		"subnets": [
			{
				"cidr":       "10.0.5.0/24",
				"rangeStart": "10.0.5.20",
				"rangeEnd":   "10.0.5.200"
			},
			{
				"cidr":       "2001:db8::0/64",
				"rangeStart": "2001:db8::100",
				"rangeEnd":   "2001:db8::f000"
			}
		],
		"routes": [
			{ "dst": "2001:db8::1/64" }
		],
		"resolvConf": "/etc/resolv.conf"
	}
}
```

Dual Stack with Request for Specific IPs:
```json
{
	"ipam": {
		"type": "host-local",
		"subnets": [
			{"cidr": "10.1.2.0/24"},
			{"cidr": "fd00:1234::0/64"}
		],
		"routes": [
			{ "dst": "fd00:1234::1/64" }
		],
		"resolvConf": "/etc/resolv.conf"
	},
	"args": {
		"cni": {
			"ips": [
				"10.1.2.20",
				"fd00:1234::1000"
			]
		}
	}
}
```

We can test it out on the command-line:

```bash
$ export CNI_COMMAND=ADD
$ export CNI_CONTAINERID=f81d4fae-7dec-11d0-a765-00a0c91e6bf6
$ echo '{ "name": "default", "ipam": { "type": "host-local", "subnet": "203.0.113.0/24" } }' | ./host-local
```

```json
{
    "ip4": {
        "ip": "203.0.113.1/24"
    }
}
```

## Network configuration reference

* `type` (string, required): "host-local".
* `subnet` (string, required if subnets not included): CIDR block to allocate out of.
* `subnets` (string, required if subnet not included): list of subnet blocks to allocate out of, where each subnet block is defined with a `cidr` and optionally `rangeStart`, `rangeEnd`, and `gateway`.
* `cidr` (string, required): CIDR block to allocate out of, used in `subnets` configuration.
* `rangeStart` (string, optional): IP inside of "subnet" from which to start allocating addresses. Defaults to ".2" IP inside of the "subnet" block.
* `rangeEnd` (string, optional): IP inside of "subnet" with which to end allocating addresses. Defaults to ".254" IP inside of the "subnet" block.
* `gateway` (string, optional): IP inside of "subnet" to designate as the gateway. Defaults to ".1" IP inside of the "subnet" block.
* `routes` (string, optional): list of routes to add to the container namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, value of "gateway" will be used.
* `resolvConf` (string, optional): Path to a `resolv.conf` on the host to parse and return as the DNS configuration
* `dataDir` (string, optional): Path to a directory to use for maintaining state, e.g. which IPs have been allocated to which containers
* `ip` (string, optional): request a specific IP address from the subnet. If it's in one of the subnets, but not available, the plugin will exit with an error
* `ips` (string, optional): request for a list of IP addresses to be allocated from the subnets. If it's in one of the subnets, but not available, the plugin will exit with an error


## Supported arguments
The following [CNI_ARGS](https://github.com/containernetworking/cni/blob/master/SPEC.md#parameters) are supported:

* `ip`: request a specific IP address from the subnet. If it's not available, the plugin will exit with an error

## Files

Allocated IP addresses are stored as files in `/var/lib/cni/networks/$NETWORK_NAME`.  The prefix can be customized with the `dataDir` option listed above.
