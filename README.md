# Zenedge add-ons for netfilter/iptables

Zentables-addons is a set of extensions to netfilter/iptables
developed by [Zenedge](http://www.zenedge.com) and
based on [Xtables-addons](http://xtables-addons.sourceforge.net/).

## Zenset

Zenset is a netfilter/iptables extension which provides support for matching
[Proxy Protocol](http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt)
source address
using [IP Set](http://ipset.netfilter.org/).

## RESET

RESET is a netfilter/iptables extension which provides support to finalize an
established TCP connection by emulating a TCP RST to both ends.
This extension is based on ipt\_REJECT.

## Usage

For example, for blocking the source address _10.10.10.10_ sent through _Proxy
Protocol_ using _TCP RST_ and a _IP set_, we can use:
```
# ipset create blacklist hash:ip
# ipset add blacklist 10.10.10.10
# iptables -I INPUT -p tcp -m zenset --proxy-protocol --match-set blacklist src -j RESET
```

## Installation

### Dependencies

```
# apt-get install libmnl-dev libltdl7-dev iptables-dev libxtables10 libipset-dev ipset

```

### Building

```
$ ./autogen.sh
$ ./configure
$ make
# make install
```

### Running

```
# depmode -a
# modprobe xt_zenset
# modprobe xt_RESET
```

