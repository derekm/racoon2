<p align="center">
  <img src="logos/nightwatch.png" alt="racoon2 Night Watch" width="180"/>
</p>

<h1 align="center">Racoon2</h1>

<p align="center">
<strong>The Racoon2 IPsec server continuation</strong><br/>
<em>IKEv1 + IKEv2 · Linux NETLINK_XFRM dataplane · iked / spmd / kinkd</em>
</p>

<p align="center">
  <a href="https://github.com/derekm/racoon2/actions/workflows/ubuntu.yml"><img src="https://github.com/derekm/racoon2/actions/workflows/ubuntu.yml/badge.svg?branch=linux-km" alt="Ubuntu build &amp; test (xfrm + pfkey)"/></a>
  <a href="https://github.com/derekm/racoon2/actions/workflows/netbsd.yml"><img src="https://github.com/derekm/racoon2/actions/workflows/netbsd.yml/badge.svg?branch=linux-km" alt="NetBSD build &amp; test"/></a>
</p>

---

This document describes the Racoon2 and the distribution kit.
You have to read doc/INSTALL and doc/USAGE to use the Racoon2
after you read this document.  Enjoy !

o Files and Directories

	README   : this file, explaining the Racoon2 distribution.
	COPYRIGHT: contains the copyright.
	NEWS     : major changes, new functionalities, etc.
	FAQ      : Frequently Asked Questions.
	doc/     : specs, memos, usage, etc.
	samples/ : configuration samples.
	lib/     : files related to the library, libracoon.a
	kinkd/   : files related to the KINK daemon.
	iked/    : files related to the IKE daemon.
	spmd/    : files related to the IPsec Security Policy Management daemon.
	pskgen/  : files related to pskgen(8)

o What is the Racoon2 ?

The Racoon2 is a system to exchange and to install security parameters
for IPsec.

This code was written by the Racoon2 Project in the WIDE Project,
Japan.  The project aimed to provide the IPsec system for FreeBSD,
NetBSD and Linux. There are some similar projects working in the
Internet community (openswan/Linux, iked/OpenBSD).

The main objective of Racoon2 is currently to evaluate it as a
possible replacement iked key exchange service (IKE) for use in
future releases of major software platforms such as *BSD and Linux.
It has iked to implement IKEv1 and IKEv2, spmd to provide security
policy management services, and kinkd to provide Kerberos based
key exchange for IPsec. At present it is unstable and very difficult
to configure. Most users will not be able to use it in its current
form without a significant level of expertise and experience with
the complexities of establishing IPsec connections. It only provides
one small piece (IKE) of a complicated system of many parts that
are needed to establish successful secured communications over the
Internet.

Racoon2 is also based on very old code and it is still very buggy.
Although Racoon2 can be configured to establish working IPsec
connections using both IKEv1 and IKEv2, in its current form, most
users who do not have experience configuring IPsec connections will
not be able to get a connection working without significant effort.
The near-term goals are to reduce the number of bugs that make
Racoon2 so difficult to configure, and to create a simpler system
for configuring connections correctly so that the level of expertise
required to use Racoon2 to establish connections can be reduced to
the point where most developers will be able to build, install,
and use Racoon2 to get working IPsec connections with minimal
effort.

Currently Racoon2 works well as an L2TP/IPsec VPN server or as
an IKEv2 VPN server running on NetBSD. Linux SAD/SPD default is
NETLINK_XFRM (`lib/if_xfrm.c`, same rcpfk_* ABI as BSD pfkeyv2,
XOR like iked's netlink.c vs rtsock.c). Linux `AF_KEY` drops
kernel→user datagrams when the socket rcvbuf fills — not the
default. Force the compat socket with:

	./configure --with-km-backend=pfkey

A userspace dataplane backend (same rcpfk_* ABI) is

	./configure --with-km-backend=userspace

That loopbacks SA/SPD to iked and optionally mirrors to
`RACOON2_DATAPLANE_SOCK`. There is no DPDK forwarding process in
this tree. Hardware offload (`XFRMA_OFFLOAD_DEV`, xfrmi) is not
wired.

IKEv2 v4-in-v4 (NAT-mode) has lived: SAD+SPD from iked+spmd, ping
through ESP. Apple NAT-T is live-proven: an iPhone over LTE comes up
behind NAT (NAT-D float 500→4500), SAD shows `encap type espinudp`
both ways, pings traverse the tunnel (`XFRMA_ALG_AUTH_TRUNC` must be
emitted — an enum `#ifdef` guard silently shipped 96-bit sha256 ICVs
and ate every RFC 4868 peer packet). IKEv1 NAT-T is proven the same
way (strongSwan initiator behind a NAT router; main+quick mode over
4500, espinudp SAD, ping 3/3). IKEv1 SPD with `peers_sa_ipaddr
"IP_ANY"` still mangles XFRM tmpls — use a concrete peer address.
IPv6-in-IPv4 remains unclaimed until `ip xfrm state`/`ip xfrm policy`
after iked+spmd show that sel. Please refer to NEWS and BUGS.

## CI

GitHub Actions builds and tests the tree on NetBSD 10 (pfkey KM,
QEMU VM) and Ubuntu (NETLINK_XFRM KM), running the same unit suite
(`kmtest`, `eaytest`, `evlooptest`, `workerstest`) on both — a
validated distribution across the pfkey and netlink backends. See
`.github/workflows/`. The upstream README's claim that Linux is
"limited functionality … pfkeyv2 only" predates the NETLINK_XFRM
backend (`lib/if_xfrm.c`, Linux default) and this week's live Apple
and IKEv1 NAT-T results.

On Linux, `make install` ships systemd units under
`/usr/lib/systemd/system` (socket activation + ProtectSystem=strict,
PrivateTmp). `systemctl enable --now racoon2.target` starts
spmd.socket then iked. Daemons use `-F`; no init.d `sleep 1`.

ikedctl is built on Linux (`--enable-admin`, default). It is a
unix-socket admin client (`/var/run/iked.sock`), not PF_KEY and not
netlink. IKE SAs:

	ikedctl show-sa isakmp
	ikedctl flush-sa isakmp
	ikedctl establish-sa isakmp inet <src> <dst>
	ikedctl vpn-connect <gateway>
	ikedctl reload-config

`reload-config` is SIGHUP: `iked_reload()` runs `ikev2_shutdown()`
before reread — all IKEv2 SAs go. `establish-sa` / `vpn-connect`
return errno (ENOENT if no selector).

Kernel SAD/SPD (not ikedctl):

	ip -s xfrm state
	ip xfrm state flush
	ip xfrm policy
	ip xfrm policy flush

Do not XOR-compile ikedctl onto `NETLINK_XFRM`.

iked on Linux uses epoll (`--disable-epoll` for select). Optional
crypto workers (`--with-crypto-workers=N`, default 0 = inline) drain
on the IKE thread. OpenSSL 3 providers (`--with-openssl-provider` /
`RACOON2_OPENSSL_PROVIDER`) and ENGINE load in `eay_init`. DH/RSA
handshake enqueue is not wired; a provider only helps if it
implements those methods on the calling thread.

Currently, the system supports the following specifications:

	Internet Key Exchange (IKEv2) Protocol
	RFC 4306, Internet Key Exchange (IKEv2) Protocol
	RFC 7296, Internet Key Exchange Protocol Version 2 (IKEv2)
	RFC 4307, Cryptographic Algorithms for Use
	          in the Internet Key Exchange Version 2 (IKEv2)
	RFC 4718, IKEv2 Clarifications and Implementation Guidelines
	RFC 5282, Using Authenticated Encryption Algorithms
	          with the Encrypted Payload of IKEv2 (AES-GCM-16)

	The Internet Key Exchange (IKE)
	RFC 2409, The Internet Key Exchange (IKE)
	RFC 3947, Negotiation of NAT-Traversal in the IKE
	RFC 3948, UDP Encapsulation of IPsec ESP Packets

	IPsec
	RFC 4303, IP Encapsulating Security Payload (ESP)
	RFC 4106, The Use of Galois/Counter Mode (GCM) in IPsec ESP
	          (AES-GCM-16)

	Kerberized Internet Negotiation of Keys (KINK)
	RFC 4430, Kerberized Internet Negotiation of Keys (KINK)

	RFC 3526, More Modular Exponential (MODP) Diffie-Hellman groups
	          for Internet Key Exchange (IKE)
	RFC 2367, PF_KEY Key Management API, Version 2

	Not implemented: RFC 9242 (IKE_INTERMEDIATE), RFC 9370
	(multiple key exchanges / ADDKE), RFC 8784 PPK.
	
The system provides three daemons: iked, kinkd and spmd.
Each daemon manages IKE, KINK and IPsec Policy respectively.


The "previous Racoon" only supports IKEv1 [RFC2409].  The Racoon2 supports
IKEv1, IKEv2 and KINK.

The Racoon2 also supports IPsec security policy management with "spmd".

The configuration is completely different too, because the Racoon2 system
supports multiple key exchange protocols as well as policy management.

We however implement IKEv1 based on the Racoon in ipsec-tools.

o What features will the Racoon2 support ?

Here is the list of features that we think to implement in a future.
This is not a complete list.  This may be changed with no announcing.

	- English documentation.
	- IKEv2: configuration payload (aka mode-config in IKEv1) in iked.
	- MIPL support (MIP6 Implementation on Linux) in iked.
	- SHISA support (WIDE MIP6 Implementation on *BSD) in iked.
	- Support graceful rekeying.
	- Configuration file converter from the "previous Racoon".
	- Easy configuration tool.

o What is the Racoon2 system structure ?

There are three daemons in the Racoon2 system.  The following picture
illustrates the relationship between the daemons in the system.
You have to run "spmd" AND one protocol daemon to establish IPsec SAs.

    +--------+                            +--------+
    |  iked  |--(spmif)--+    +--(spmif)--|  kinkd |
    +--------+           |    |           +--------+
         |             +--------+             | 
         |             |  spmd  |             | 
         |             +--------+             | 
         |                  |                 |
         |                  |                 |
    --(PFKEY)------------(PFKEY)-----------(PFKEY)--
         |                  |                 |
         |                  |                 |
    +---------------------------------------------+
    |                    Kernel                   |
    +---------------------------------------------+

"spmd" is the IPsec security policy management daemon.  It has two missions.
First one is to manage IPsec policies.  "spmd" will install IPsec policies
and delete them from the kernel.  It uses PF_KEYv2 for this purpose.
Another is to cache the mapping table between IP addresses and FQDNs
for KINK processing.

"iked" processes the IKE protocol.  It initiates the protocol, and processes
the packet from the remote system.  Then it installs IPsec SAs into the
kernel by using PF_KEYv2.  If generating IPsec policies as the result of
the exchange, it also requests "spmd" to install the policies by using "spmif",
which is an abbreviation of spmd interface.

"kinkd" is similar to "iked" except that it processes the KINK protocol.

o Contact Points

Informations about the Racoon2 are available at the project's web page:

	http://www.racoon2.wide.ad.jp/

If you have any questions about the Racoon2, you can ask to the mailing
list:

	racoon2-users@racoon2.wide.ad.jp

Before sending your question, you MUST subscribe this mailing list
by sending a request in the body:

	subscribe

to racoon2-users-ctl@racoon2.wide.ad.jp.  You will receive a confirmation
from the mailing list owner.  Then you have to reply to the mail in order
to complete the procedure.

Please don't ask them to other mailing lists such as "racoon@kame.net",
"kame-snap@kame.net", or "ipsec-tools-users@lists.sourceforge.net".

If you want to help us or if you want to contribute, please contact us.
Please feel free to post any patches, make suggestions, etc.
In particular, to check English documentations is very helpful for us.

o Copyright

Basically this kit follows the BSD-like copyright.  See the file: COPYRIGHT.
In short, the code is freely available but with no warranty.

The copyright holder is WIDE Project instead of the Racoon2 Project.
This is because the Racoon2 Project belongs to the one of the working groups
in the WIDE Project.

o IPR consideration

The Racoon2 Project takes no position regarding the validity or scope of 
any intellectual property rights or other rights that might be 
claimed to pertain to the implementation or use of the technology 
used in the Racoon2, or the extent to which any license under such rights 
might or might not be available; nor does it represent that it has 
made any independent effort to identify any such rights.

The Racoon2 Project simply reproduces the intellectual property rights 
statements that have been submitted to the IETF at 
<https://datatracker.ietf.org/public/ipr_disclosure.cgi> concerning 
the IETF protocols embodied in the Racoon2.

Certicom's Statement About IPR Claimed in RFC 3526, RFC 2409, 
draft-ietf-ipsec-ikev2, and Other IETF Specifications Using MODP 
Groups: 
<https://datatracker.ietf.org/public/ipr_detail_show.cgi?&ipr_id=336>

Internet Key Exchange (IKEv2) Protocol: 
<https://datatracker.ietf.org/public/ipr_detail_show.cgi?&ipr_id=137>

Microsoft's statement about IPR claimed in 
draft-ietf-ipsec-ikev2-08.txt: 
<https://datatracker.ietf.org/public/ipr_detail_show.cgi?&ipr_id=190>

If you have a concern about the possible intellectual property rights 
associated with acquiring, compiling, modifying, or otherwise using 
the Racoon2 software, you should consult your own attorney.

o Project Members

Core project members are:

	Satoshi Inoue       Panasonic Communications Co., Ltd.
	Atsushi Fukumoto    Toshiba Corporation
	Mitsuru Kanda       Toshiba Corporation
	Kazunori Miyazawa   Yokogawa Electric Corporation
	Ken'ichi Kamada     Yokogawa Electric Corporation
	Shoichi Sakane      Yokogawa Electric Corporation
	Francis Dupont

	Alphabetical order of the name of their belonging company.

o Acknowledgments

Thanks to Paul Hoffman.  He suggested what we should think about the
intellectual property rights related the IKEv2 protocol, and helped us
to publish our IKEv2 code.  Thanks to member of the WIDE project.
We could not work without the great project.

Thanks to Yutaka Yamashita.  He implemented the partial mobility support
with SHISA (http://www.mobileip.jp/) in iked(8).

[![Build Status][status]][travis]

[BUILDING]: BUILDING
[status]: https://travis-ci.org/zoulasc/racoon2.svg?branch=master
[travis]: https://travis-ci.org/zoulasc/racoon2
