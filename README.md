# tcxflow

**Lightweight eBPF-based IPFIX flow accounting for Linux.**

tcxflow meters the traffic of selected network interfaces with a small eBPF program
on the kernel's tcx hook and exports the flows as IPFIX (RFC 7011) to one or more
collectors. It replaces `ipt_NETFLOW` on modern systems: no out-of-tree kernel module,
no iptables or nftables rules, and it works on routers whose interfaces live in a
separate network namespace.

## Features

- One small C binary with libbpf as the only dependency; the BPF program is embedded.
- Per interface, inbound and/or outbound; up to 64 interfaces and 8 collectors.
- IPv4 and IPv6, including extension headers and fragments; ports of TCP, UDP, UDP-Lite, SCTP and DCCP.
- VLAN-aware: 802.1Q and QinQ VLAN IDs are part of each flow and exported.
- Works on any interface type: NICs, bonds, bridges, VLAN, VXLAN, WireGuard, mirror ports.
- Counts what is on the wire: GRO/TSO and BIG TCP packets as their real segments, layer 3 bytes.
- Never drops or changes packets. It runs in front of other tcx programs, which cannot hide
  packets from it.
- `tcxflow stats` and `tcxflow interfaces` query the running exporter.
- About 60 ns per packet with warm caches, 160–290 ns under real gigabit traffic (Pentium
  G4560, Core i5-10210U).

## Requirements

| Distribution | Kernel | Build dependencies |
|---|---|---|
| Debian 13 (trixie) and later | 6.12 | `apt install make gcc clang libbpf-dev bpftool pkg-config` |
| Fedora 44 and later | ≥ 6.12 | `dnf install make gcc clang libbpf-devel bpftool pkgconf-pkg-config` |
| AlmaLinux 10 and later | 6.12 | `dnf install make gcc clang libbpf-devel bpftool pkgconf-pkg-config` (libbpf-devel is in CRB, enabled by default since 10.1) |

In general: Linux ≥ 6.6 (tcx) with BTF (`CONFIG_DEBUG_INFO_BTF`, enabled by all of the
distributions above) and libbpf ≥ 1.5. Building needs a C23 compiler (GCC ≥ 14 or clang ≥ 19),
clang ≥ 19 for the BPF program, and bpftool. tcxflow runs as root, or with `CAP_BPF`, `CAP_NET_ADMIN`,
`CAP_PERFMON` (the BPF program reads the packet's network header offset from the kernel) and,
for `netns`, `CAP_SYS_ADMIN`.

Tested with Debian 13 (GCC 14.2, clang 19, libbpf 1.5), AlmaLinux 10.2 (GCC 14.3, clang 21,
libbpf 1.7) and Fedora 44 (GCC 16.2, clang 22, libbpf 1.6.3), built with GCC and with clang, on
their kernels 6.12 and 7.2, and with Debian 13 on mainline Linux 6.6.

## Installation

### Packages

Every release has signed packages for Debian 13 and AlmaLinux 10, attached to the GitHub
release and in APT and DNF repositories at https://dnehring7.github.io/tcxflow/:

```bash
# Debian 13 (trixie)
sudo curl -fsSL https://dnehring7.github.io/tcxflow/debian/tcxflow.sources \
  -o /etc/apt/sources.list.d/tcxflow.sources
sudo apt update && sudo apt install tcxflow

# AlmaLinux 10
sudo curl -fsSL https://dnehring7.github.io/tcxflow/almalinux/10/tcxflow.repo \
  -o /etc/yum.repos.d/tcxflow.repo
sudo dnf install tcxflow
```

The packages install `/usr/sbin/tcxflow`, the systemd unit and `/etc/tcxflow/tcxflow.conf`.
The service is not enabled: edit the configuration first (see below). `tcxflow --version`
prints the version.

### From source

```bash
git clone https://github.com/dnehring7/tcxflow.git
cd tcxflow
make
sudo make install    # /usr/local/sbin/tcxflow, the systemd unit, /etc/tcxflow/tcxflow.conf
```

`make install` keeps an existing `/etc/tcxflow/tcxflow.conf`. `PREFIX=/usr` installs to
`/usr/sbin` and `/usr/lib/systemd/system`, `SYSCONFDIR` moves the configuration (the binary and
the unit look for it there too), and `DESTDIR` stages the files for a package.
`sudo make uninstall` removes the binary and the unit, but not the configuration.

Edit `/etc/tcxflow/tcxflow.conf`, then:

```bash
sudo tcxflow check                  # validate the configuration
sudo systemctl daemon-reload
sudo systemctl enable --now tcxflow
systemctl status tcxflow
```

The unit (`tcxflow.service`) keeps only `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` and `CAP_SYS_ADMIN`, sees
the file system read-only and restarts tcxflow whenever it exits.

## Configuration

The configuration file holds the same options as the command line, one per line:

```bash
# /etc/tcxflow/tcxflow.conf
netns            dataplane
interface        eth0
interface        eth1:in
collector        192.0.2.10:2056
collector        192.0.2.10:2058
inactive-timeout 15
active-timeout   120
```

| Option | Value | Default |
|---|---|---|
| `interface` | `NAME`, `NAME:in`, `NAME:out` or `NAME:both`; repeat for more interfaces (max. 64) | both directions |
| `collector` | `host:port` or `[ipv6]:port`; repeat for more collectors (max. 8) | port 4739 |
| `netns` | network namespace of the interfaces: name in `/run/netns` or an absolute path | tcxflow's own |
| `inactive-timeout` | export a flow after this many seconds without packets (1–86400) | 15 |
| `active-timeout` | export long-running flows at least this often, in seconds (1–604800) | 1800 |
| `max-flows` | BPF flow table size per one-second interval (1024–16777216) | 131072 |
| `cache-flows` | flows cached until they end, at most (1024–134217728) | 8 × `max-flows` |
| `observation-domain` | IPFIX observation domain id (0–4294967295) | 1 |
| `template-refresh` | send the IPFIX templates at least this often, in seconds (1–86400) | 60 |
| `export-interval` | send a partly filled IPFIX message after this many seconds (0–60; 0: every second) | 10 |
| `socket` | control socket for `stats` and `interfaces`, an absolute path | `/run/tcxflow/tcxflow.sock` |

`option value` and `option = value` are both accepted, and `#` starts a comment.
Errors name the file and line.

On the command line the same options take two dashes (`--interface eth0`), and `-i` and
`-s` are short for `--interface` and `--socket`. Command line options apply on top of the
configuration file. When interfaces or collectors are given there, `/etc/tcxflow/tcxflow.conf`
is not read, so a quick test does not mix with the installed configuration:

```bash
sudo tcxflow --netns dataplane -i eth0 --collector 192.0.2.10:4739
```

Options only for the command line:

| Option | |
|---|---|
| `-c`, `--config FILE` | read this configuration file instead of `/etc/tcxflow/tcxflow.conf`, always |
| `-v`, `--verbose` | also show libbpf's informational and debug messages |
| `-V`, `--version` | print the version and exit |
| `-h`, `--help` | show the options and exit |

## Commands

```
tcxflow [OPTIONS] [run|stats|interfaces|check]
```

| Command | |
|---|---|
| `run` (default) | run the exporter in the foreground; systemd starts it like this |
| `stats` | counters of the running exporter |
| `interfaces` | metered interfaces, their state and traffic |
| `check` | validate the configuration and resolve the collectors, then exit |

The exit status is 0 on success, 1 on errors and 2 for an invalid command line. Errors include
a metered interface or the namespace that disappears, flow maps that cannot be drained for
10 seconds, and messages of the final export that could not be sent.

```
$ sudo tcxflow stats
version            v1.1.0
uptime             3h 12m 5s
cpu                41.718 s (0.362% of one CPU), max RSS 14212 KiB
tick               last 1873 us, max 9541 us
netns              dataplane
interfaces         2 attached, 0 gone
packets            918273645
bytes              712398123456
ignored            12 non-IP, 0 malformed
lost               0 packets, 0 bytes (flow table full, max_flows 131072)
flows cached       5321 (at most 1048576)
cache memory       7616 KiB allocated
flows uncached     0 (cache full: exported at once)
flows exported     1288210
ipfix messages     59102
collector          192.0.2.10:2056: 59102 sent, 0 errors

$ sudo tcxflow interfaces
INTERFACE       IFINDEX VLAN      DIRECTION STATUS       IN PACKETS         IN BYTES    OUT PACKETS        OUT BYTES
eth0                  4 -         in+out    attached      512339871     401923847221      402104421     310264123331
eth1.100              7 100       in        attached       10272231       8019220177              0                0
```

`stats` and `interfaces` talk to the running exporter over the control socket; they need the
same privileges as the socket (root by default). A lock file next to it keeps a second tcxflow
from starting, and tcxflow never replaces a socket another program listens on; one left behind
by a crashed tcxflow is replaced. `cpu` and `tick` show what tcxflow itself costs: its CPU time
since the start, and how long the once-per-second work took. `cache memory` is what the flow
cache has allocated: it stays at its largest size, up to `cache-flows`.

## How it works

```
 network namespace "dataplane"                tcxflow (userspace), once per second
 ┌───────────────────────────────────┐        ┌──────────────────────────────────┐
 │ eth0 ─ tcx ingress ─┐             │        │ 1. switch the active map 0 <-> 1 │
 │      └ tcx egress ──┤ BPF program │        │ 2. drain the idle map            │
 │ eth1 ─ tcx ingress ─┤             │        │ 3. merge into the flow cache     │
 │      └ tcx egress ──┘             │        │ 4. expire: inactive, active, FIN │
 │               │                   │        │ 5. send IPFIX to the collectors  │
 │   flows0 / flows1 (BPF hash maps) │◄──────►│ control socket: stats/interfaces │
 └───────────────────────────────────┘        └──────────────────────────────────┘
```

The BPF program only writes to the active map, and tcxflow only reads the idle one.
`active` is an array of maps, and the kernel waits until every running BPF program has
finished before an update of it returns. After the switch, no packet can still be
counted into the idle map, so no counter update gets lost. The maps only need to hold one
second of traffic. Timeouts, aggregation and the IPFIX encoding run in userspace.

What it costs:

- **Per packet** (kernel): one hash lookup in a preallocated BPF map and two atomic adds;
  a new flow adds one insert. No memory allocation, no locks held across packets.
- **Per second** (userspace): work in proportion to the flows that had packets or ended in
  that second, never to all cached flows. A hash table finds a flow, and lists in time order
  let the expiry stop at the first flow that is still running. With 1 million cached but quiet
  flows, tcxflow uses about 1% of one CPU, almost all of it in the kernel's walk of the
  drained map (see Sizing); a full scan of the cache, as older designs do, cost 7%.
- **Memory** is allocated up front or reused: the BPF maps are preallocated, freed cache
  entries are reused, and the cache has a hard limit. tcxflow does not grow over time: in a
  40-minute run at 20,000 new flows per second (38 million flows exported), RSS stayed flat
  at 35 MiB after warm-up, with a constant number of file descriptors, and LeakSanitizer
  found nothing in a second instance metering the same traffic. Both counted every packet.

### The end-to-end test

`sudo make test-e2e` (`tests/e2e.sh`) builds a small routed network out of network
namespaces, runs tcxflow in a management namespace with `netns` and two nfcapd collectors as
IPFIX sinks, and checks the decoded records against traffic with known counts:

- ICMP, UDP, IPv6 and router-originated traffic: exact packet and byte counts;
- VLAN 300 and QinQ 400/500 on a trunk and on a VLAN interface: the right VLAN IDs;
- a 50 MB TCP transfer: exactly the segments the kernel sent, retransmissions included;
- a long flow: split by the active timeout into several records that add up exactly;
- `tcxflow stats` and `tcxflow interfaces`; both collectors received the same records, field
  by field; tcxflow stops with status 0;
- a second tcxflow on the same control socket: it must refuse to start;
- a collector that restarts: it must decode the first message it gets afterwards;
- replacing a metered interface by one with the same name and index, and deleting the
  namespace, under a running tcxflow: it must exit with status 1 both times.

The namespaces get unique names, and tcxflow and its collectors run in their own, so the test
is safe on a live host. Set `TCXFLOW=` to run another binary, for example a wrapper that starts
tcxflow under valgrind.

### What is exported

Two IPFIX templates are used, 256 for IPv4 and 257 for IPv6. Each record contains:

- source and destination address and port
- `icmpTypeCode`, `protocolIdentifier`, `ipClassOfService`, `tcpControlBits`
- `ingressInterface`, `egressInterface`, `flowDirection`
- `vlanId`, `dot1qCustomerVlanId` on ingress records, `postVlanId`,
  `postDot1qCustomerVlanId` on egress records (see [Interface types and VLANs](#interface-types-and-vlans))
- `packetDeltaCount`, `octetDeltaCount`
- `flowStartMilliseconds`, `flowEndMilliseconds`, `flowEndReason`

Templates are repeated every 60 seconds (`template-refresh`) and every 20 messages, also while
no flow ends; they never wait for `export-interval`. A collector that refused a message (it was down or restarted) gets them before
that message is sent again, and one that missed a message before the next; the other
collectors are not affected. tcxflow logs when a collector refuses or messages cannot be sent,
and when it is reachable again. Messages are sized to fit the path MTU towards every collector
(112 to 1400 bytes; 464 if it is unknown, for 512-byte packets as RFC 7011 asks), so exporting
through a VPN or tunnel does not fragment them. Below 284 bytes the templates go in messages
of their own. When many flows end at once and a socket buffer fills up, tcxflow waits for the
collector up to 200 ms per second, and up to 5 seconds for the final export at shutdown.

How the counting works:

- **Where it counts.** tcxflow counts on the interface, like the NetFlow of a hardware
  router. Ingress is measured before DNAT and egress after SNAT, and the counts include
  packets the firewall drops later.
- **Other tcx programs** on the same interface run after tcxflow: it attaches in front of the
  programs already there, so their verdicts (drop, redirect, or `TCX_PASS`, which ends the
  chain, as Cilium's programs return) cannot hide packets from it. On egress it sees packets
  before such programs rewrite them. A program attached later in front of all others runs
  before tcxflow.
- **One record per interface and direction.**
  - Ingress records have no egress interface yet, because the routing decision comes later.
  - Egress records of forwarded traffic carry the interface the packet came in on.
    Traffic the host sends itself has ingress interface 0.
- **Flows end** after the inactive timeout, after the active timeout, 2 seconds after the
  last packet of a TCP connection that sent FIN or RST, or when tcxflow stops (`forcedEnd`),
  within about one second of the timeout. Packets that come after such a gap start a new
  record, even if they arrive before the old one was exported: a new connection on the same
  ports gets its own. SIGTERM, SIGINT and SIGHUP all export every cached flow before tcxflow
  exits.
- **Super-packets** (GRO, TSO, BIG TCP) count as the segments they become on the wire, each
  with its own headers. The Jumbo Payload header Linux puts on IPv6 BIG TCP packets in the
  stack is not on the wire and not counted; real IPv6 jumbograms (RFC 2675) count as they are.
- **Fragments.** The first fragment of a datagram carries the ports and counts with them; the
  later ones form a flow without ports. An IPv4 first fragment that ends inside the transport
  header counts without ports too.
- **Malformed packets** are not assigned to any flow: length fields that contradict the
  headers or the frame, UDP lengths below 8 or beyond the IP payload, TCP data offsets below 5,
  IPv6 Authentication Headers shorter than 12 bytes, IPv6 first fragments without the whole
  transport header. The kernel drops such packets, and their fields would be guesses.
  `tcxflow stats` counts them as `malformed`. IPv6 chains of more than 6 extension headers
  (each one once, destination options twice, as RFC 8200 recommends) count without ports, with
  the header where parsing stopped as the protocol.
- **Flows are keyed by the DSCP,** not by the ECN bits, which change within a connection
  (handshake not-ECT, data ECT(0), CE under congestion) and would split it into several flows.
  `ipClassOfService` is the flow's DSCP with the ECN bits of its first packet.
- **What it does not do:** NetFlow v9 output, NAT event logging and sampling. With tunnel
  offloads (VXLAN, Geneve, GRE segmentation by the NIC), every segment repeats the inner
  headers too, but only the outer ones are counted per segment: bytes of such overlay traffic
  come out a few percent low on the underlay interface.

## Interface types and VLANs

tcx works on every kind of network interface, so tcxflow can meter any of them. What it
counts depends on where it is attached:

| Attached to | Counts |
|---|---|
| Physical NIC, bond, bridge, veth | all IP traffic crossing it; tagged traffic with its VLAN IDs |
| VLAN interface (`eth0.100`, QinQ `eth0.100.200`) | the traffic of that VLAN, with its VLAN ID(s) |
| VXLAN device (`vxlan0`) | the inner (tenant) flows; the underlay NIC sees UDP 4789 |
| WireGuard device (`wg0`) | the decrypted flows; the underlay NIC sees UDP 51820 |
| Mirror or SPAN port | the mirrored traffic: use `NAME:in` and `ip link set NAME promisc on` |

All of these are tested; VLAN, QinQ and the counts on a trunk are part of the end-to-end
test.

**VLANs.** The VLAN IDs are part of every flow, so the same addresses in two VLANs (tenants
reusing one network) stay two flows.

- On a trunk (`eth0`), the outer VLAN ID comes from the packet's metadata: the NIC or the
  kernel removes the tag on the way in and adds it only after tcxflow on the way out. A
  second tag (QinQ) is read from the packet.
- On a VLAN interface (`eth0.100`) packets carry no tag any more; tcxflow takes the VLAN
  ID(s) from the interface configuration (`/proc/net/vlan/config` of the namespace). Metering
  `eth0` or `eth0.100` gives the same VLAN ID.
- Exported per direction, like the interfaces: ingress records carry `vlanId` and, for QinQ,
  `dot1qCustomerVlanId`; egress records `postVlanId` and `postDot1qCustomerVlanId`. Untagged
  traffic has 0.
- nfdump shows the VLAN with `%svln`/`%dvln` and filters with `vlan 100`; nfdump 1.7 shows
  the QinQ customer VLAN only in its JSON output (`cust_vlanID`, `post_cust_vlanID`).
- `tcxflow interfaces` shows the VLAN of each metered VLAN interface.

## Network namespaces

A network namespace is a separate copy of the Linux network stack. It has its own
interfaces, addresses, routing tables, firewall and sockets. Routers often use one to
separate forwarding from management:

```
root namespace                         namespace "dataplane"
  mgmt0: SSH, monitoring, collectors     eth0, eth1: uplinks, customer ports
                                         the routing table that forwards traffic
```

```bash
ip netns add dataplane                 # creates /run/netns/dataplane
ip link set eth0 netns dataplane       # moves an interface into it
ip -n dataplane link                   # interfaces as seen inside, with their ifindex
ip netns exec dataplane ip route       # runs any command inside
```

What matters for flow accounting:

- **Hooks are per namespace.** Traffic forwarded inside `dataplane` never passes the
  netfilter hooks of the root namespace, so global hooks there see nothing. tcxflow
  attaches to the interfaces themselves and meters exactly what crosses them.
- **Interface indexes are per namespace.** `ingressInterface` and `egressInterface` are
  the ifindexes inside the interfaces' namespace. `tcxflow interfaces` shows the mapping,
  and so does `ip -n dataplane link`.
- **Export leaves from where tcxflow runs.** With `netns dataplane`, tcxflow first opens
  its collector sockets and the control socket in its own namespace (normally the root
  namespace, where the management network is). Only then does it switch to `dataplane`
  to attach to the interfaces. The collectors do not need to be reachable from the
  dataplane.
- If the collectors are reachable from inside the namespace, you can run tcxflow there
  instead: `ip netns exec dataplane tcxflow …` without `netns`.
- **Namespaces of other tools.** `netns` also accepts a path. Bind mounts such as
  `/run/docker/netns/<id>` work as they are. For `/proc/<pid>/ns/net` the kernel requires
  ptrace access to that process, which the systemd unit does not grant (it lacks
  `CAP_SYS_PTRACE`). Give the namespace a name instead, with
  `ip netns attach dataplane <pid>`, and use `netns dataplane`.
- **Interfaces and namespaces that disappear.** If an interface disappears (also when it is
  replaced by one with the same name and index: the kernel detaches the BPF programs from the
  old one), or the namespace is deleted or rebuilt, tcxflow exports what it has and exits with
  status 1, so it never
  keeps a deleted namespace (and the interfaces in it) alive. systemd restarts it, and it
  attaches again. If another unit creates the namespace, order tcxflow after it with
  `systemctl edit tcxflow` (`After=` and `Requires=`).

## Sizing

- **`max-flows`** is the number of distinct flows tcxflow can track per second. There
  are two maps of that size; the default of 131072 uses about 40 MiB of kernel memory.
  Draining a map once per second walks all of its slots, about 5 ns each: 1 ms per second
  at the default, 6 ms at 1048576. Make it as large as needed, not larger.
- **When the table is full,** packets of new flows in that second are not counted.
  They show up as `lost` in `tcxflow stats`, with a warning in the log. Size it for
  your busiest second, with headroom.
- **The flow cache** in userspace holds the flows until they end, at most `cache-flows` (8 ×
  `max-flows` by default; about 116 bytes each: 1 Mi flows and 116 MiB). Long quiet flows need
  more of it than a busy second needs table slots, so the two are set apart. When it is full, for example during a
  flood with spoofed source addresses, flows that are not cached yet are exported every
  second with `flowEndReason` 5 (lack of resources) instead. Counts stay exact, but there
  are more records. `tcxflow stats` shows them as `flows uncached`.

## Development

| Target | |
|---|---|
| `make` | build `./tcxflow` |
| `make dev` | strict build of `tcxflow` and the tests: every warning is an error |
| `make test` | unit tests: configuration, collectors, control socket, interfaces, VLAN lookup, IPFIX encoding, flow cache; the BPF program compiled natively for BIG TCP, jumbograms and races between CPUs (no root) |
| `sudo make test-bpf` | BPF program tests: hand-built packets via `BPF_PROG_TEST_RUN` |
| `sudo make test-e2e` | end-to-end test in network namespaces against nfdump (needs nfdump, iperf3) |
| `sudo make test-all` | all three |
| `make indent` | format with clang-format (`.clang-format`) |
| `make check-indent` | fail if a file is not formatted |
| `make lint` | clang-tidy (`.clang-tidy`), one stamp per file, parallel (`NJOBS=`); shellcheck for `tests/*.sh` |
| `make check` | `check-indent`, `lint`, `make dev` and the unit tests |
| `make docs` | Doxygen documentation in `docs/html` |
| `make dist` | source tarball `../tcxflow-VERSION.tar.gz` of the committed `HEAD` |
| `sudo make install` | binary, systemd unit and example configuration (`PREFIX`, `DESTDIR`) |
| `sudo make uninstall` | remove the binary and the unit |
| `make clean` | remove everything the build created |

- C23 (`-std=gnu23`) for tcxflow and the BPF program; the BPF program uses instruction set v4
  (Linux 6.6). bpftool links the BPF object, dropping its DWARF but keeping the BTF, and
  generates `build/tcxflow.skel.h`, which embeds the object and names its maps and programs.
- `make dev` (or `DEV_WARNINGS=1` on any target) builds with `-Werror` and a long list of
  extra warnings (`-Wconversion`, `-Wshadow`, `-Wcast-qual`, `-Wformat=2`, …), the GCC static
  analyzer (`-fanalyzer`), `_FORTIFY_SOURCE=3` and stack protection. The BPF program is
  compiled with `-Werror` too. A normal `make` stays lenient, so a newer compiler cannot break
  a distribution build.
- Switching between `make`, `make dev` and `SANITIZE=address` rebuilds everything: every object
  depends on the flags it was built with.
- `make SANITIZE=address` builds with ASan and UBSan.
- `CFLAGS`, `CPPFLAGS` and `LDFLAGS` belong to the packager (`make CFLAGS="$RPM_OPT_FLAGS"`);
  the flags tcxflow needs are added separately, so they cannot be overridden by accident.
- CI formats and lints with clang-format and clang-tidy 22 (`pipx install clang-format==22.1.8 clang-tidy==22.1.8`).
- GitHub Actions (`.github/workflows/ci.yml`, Ubuntu 26.04 runners) runs `make check` and
  `make docs` on Debian 13 (the oldest supported toolchain), builds and unit-tests with GCC and
  clang on Debian 13, Fedora 44 and AlmaLinux 10, and runs the BPF and end-to-end tests on the
  runner itself (Linux 7.0, GCC 15, clang 21, libbpf 1.6).

### Releases and packages

The version is in `src/util.h` (`TCXFLOW_VERSION`, for example `v1.1.0`, the same as the git
tag) and in `tcxflow.spec` (`Version`, without the `v`). To release, set both, commit, and push
the tag, for example `v1.1.0`. Only such a tag starts `.github/workflows/release.yml`, which
fails if the code is not at the version of the tag:

- **ci**: all of `ci.yml`, including the BPF and end-to-end tests on the runner's kernel.
- **rpm** (AlmaLinux 10) and **deb** (Debian 13): the package, with the distribution's compiler
  flags and the unit tests; it must install and report the version of the tag. The rpm job
  signs the RPMs.
- **publish**: signed APT and DNF repositories on GitHub Pages, with a page with the
  installation commands, and the packages attached to the GitHub release.

Signing needs the repository secret `GPG_PRIVATE_KEY` (the armored, unencrypted private key)
and its public key in the owner's GitHub profile: the repository configs fetch it from
`https://github.com/dnehring7.gpg`. The `github-pages` environment must allow deployments from
the tags `v*` (Settings → Environments).

The packages also build by hand. `debian/changelog` is written by the release workflow, so create one
first:

```bash
dch --create --package tcxflow --newversion 1.1.0 --distribution trixie 'Release 1.1.0'
dpkg-buildpackage -us -uc -b            # ../tcxflow_1.1.0_amd64.deb

git archive --prefix=tcxflow-1.1.0/ -o tcxflow-1.1.0.tar.gz v1.1.0
rpmbuild -ta tcxflow-1.1.0.tar.gz       # ~/rpmbuild/RPMS/x86_64/
```

Source layout:

| File | |
|---|---|
| `src/tcxflow.bpf.c` | BPF program (tcx ingress/egress) |
| `src/flow.h` | flow key, counters and statistics shared with the BPF program |
| `src/meter.c` | loads, attaches, swaps and drains the BPF side (libbpf, through the skeleton bpftool generates) |
| `src/cache.c` | flow cache with inactive, active and FIN timeouts |
| `src/ipfix.c` | IPFIX message encoder |
| `src/daemon.c` | the exporter loop and the control commands |
| `src/control.c` | control socket |
| `src/config.c` | options and configuration file |
| `src/collector.c` | collector addresses and sockets |
| `src/iface.c` | metered interfaces: lookup by ifindex, VLAN IDs of their records |
| `src/vlan.c` | VLAN IDs of VLAN interfaces |
| `src/util.c` | logging and clocks |
| `src/main.c` | command line |
| `tests/test_unit.c` | unit tests |
| `tests/test_bpf.c` | BPF program tests |
| `tests/test_bpf_native.c` | the BPF program as ordinary C, with the helpers in `tests/native/` |
| `tests/e2e.sh` | end-to-end test |
| `debian/` | Debian package |
| `tcxflow.spec` | RPM package |
| `.github/workflows/ci.yml` | GitHub Actions: lint, builds and tests on every push |
| `.github/workflows/release.yml` | release tags: packages, repositories, GitHub release |
| `.github/copilot-instructions.md` | coding rules for AI assistants |

## License

GPL-2.0-or-later, see the file `LICENSE`. Copyright (C) 2026 Dirk Nehring.

One license for all of tcxflow, chosen to be compatible with the kernel (GPL-2.0-only), which
runs the BPF program: the program declares "GPL" to the kernel, which means GPL v2 or later.
