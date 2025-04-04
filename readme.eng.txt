This project is intended to fight DPI protocol analysis and bypass protocol blocking.

One of the possible ways to overcome DPI signature analysis is to modify the protocol.
The fastest but not the easiest way is to modify the software itself.
For TCP, obfsproxy exists. However, in the case of VPN - only not very fast solutions (openvpn) work over TCP.

What to do in case of udp?
If both endpoints are on a external IP, then its possible to modify packets on IP level.
For example, if you have a VPS, and you have an openwrt router at home and external IP from ISP,
then you can use this technique. If one endpoint is behind NAT, then abilities are limited,
but its still possible to tamper with udp/tcp headers and data payload.

The scheme is as follows:
 peer 1 <=> IP obfuscator/deobfuscator <=> network <=> IP obfuscator/deobfuscator <=> peer 2

In order for a packet to be delivered from peer 1 to peer 2, both having external IPs,
it is enough to have correct IP headers. You can set any protocol number, obfuscate or encrypt IP payload,
including tcp / udp headers. DPI will not understand what it is dealing with.
It will see non-standard IP protocols with unknown content.

ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid

The XOR operation is symmetric, therefore the same parameters are set for the obfuscator and deobfuscator.
On each side, one instance of the program is launched.

Filtering outgoing packets is easy because they go open, however, some u32 is required for incoming.
The protocol number ("-p") in the filter is the result of the xor of the original protocol with ipproto-xor.

server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16  -j NFQUEUE --queue-num 300 --queue-bypass

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16  -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=128 --data-xor=0x458A2ECD --data-xor-offset=4 --data-xor-len=44

Why data-xor-offset = 4: tcp and udp protocol headers start with source and destination port numbers, 2 bytes each.
To make it easier to write u32 do not touch the port numbers. You can touch, but then you have to figure out into what
numbers original ports will be transformed and write those values to u32.
Why data-xor-len = 44: an example is given for wireguard. 44 bytes is enough to XOR the udp header and all wireguard headers.
Next come the encrypted wireguard data, it makes no sense to XOR it.

You can even turn udp into "tcp trash" with ipproto-xor = 23. According to the ip header, this is tcp, but in place of the tcp header is garbage.
On the one hand, such packets can go through middle-boxes, and conntrack can go crazy.
On the other hand, it may even be good.

There are nuances with ipv6. In ipv6 there is no concept of a protocol number. But there is the concept of "next header".
As in ipv4, you can write anything there. But in practice, this can cause ICMPv6 Type 4 - Parameter Problem messages.
To avoid this, you can cast the protocol to the value 59. It means "no Next Header".
To get "ipproto-xor" parameter, XOR original protocol number with 59.

udp : ipproto-xor=17^59=42
tcp : ipproto-xor=6^59=61

server ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "40&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --sport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

client ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "38&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --dport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=61 --data-xor=0x458A2ECD --data-xor-offset=4

IP FRAGMENTATION
If the sending host sends too long packet, it is fragmented at the IP level.
The receiving host only reassembles packets addressed to the host itself.
In the PREROUTING chain packets are still fragmented.
When applying deobfuscation only to a part of the packet, the cheksum inevitably becomes invalid.
csum = fix does not help.
For ipv4, adding a rule to the INPUT chain instead of PREROUTING helps.
Of course, only packets addressed to the host itself are caught, but they come
in NFQEUEUE in already assembled state and correctly deobfuscated.
IP fragmentation is an undesirable, it should be combated by setting the correct MTU
inside the tunnel. There are some protocols that rely on ip fragmentation. These include IKE (without rfc7383).

IPV6 FRAGMENTATION
Fragmentation is also possible in ipv6, however, it is performed only by the sending host, usually only for
udp and icmp when the frame does not fit into mtu. The header "44" is added to all fragments immediately after the ipv6 header.
Unfortunately, all attempts to catch the reconstructed full frame in various tables failed.
Only the first fragment is caught. It was not possible to find out the reason. Is this a bug or feature is known only to Torvalds.

CHECKSUMS :
Work with checksums begins when a tcp or udp packet passes through the obfuscator.
For incoming packets, the ipproto-xor operation performed first, and after that it is analyzed whether it is tcp or udp.
For outgoing, the opposite is true.
--csum=none - do not touch checksums at all. if after deobfuscation checksum is invalid, the system will discard the packet.
--csum=fix - checksum ignore mode. its not possible to disable checksum verification inside NFQUEUE.
Instead, on incoming packets checksum is recomputed and replaced, so the system will accept the packet.
--csum=valid - bring the checksum to a valid state for all packets - incoming and outgoing.
This mode is useful when working through NAT which blocks invalid packets.

Recomputing checksum increases cpu usage.
See also section "NAT break".


DISADVANTAGE :
Each packet will be thrown into nfqueue, therefore the speed will decrease significantly. 2-3 times.
If you compare wireguard + ipobfs with openvpn on a soho router, then openvpn will still be slower.


ipobfs_mod
-----------

The same as ipobfs, but implemented as a linux kernel module. It gives a performance drop of only 20%.
It duplicates ipobfs logic and is compatible with it.

Its possible to use ipobfs on peer1 and ipobfs_mod on peer2, they will work together.
However, by default ipobfs_mod will produce tcp and udp packets with invalid cheksums, the system
with ipobfs will discarded them. Use csum=fix on ipobfs_mod side.

The iptables commands are the same, but instead of "-j NFQEUEUE" use "-j MARK --set-xmark".
ipobfs_mod performs packet processing based on fwmark.

Settings are passed through the kernel module parameters specified in the insmod command.

server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16 -j MARK --set-xmark 0x100/0x100

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16 -j MARK --set-xmark 0x100/0x100

rmmod ipobfs
insmod /lib/modules/`uname -r`/extra/ipobfs.ko  mark=0x100 ipp_xor=128 data_xor=0x458A2ECD data_xor_offset=4 data_xor_len=44

The module supports up to 32 profiles. Parameter settings for each profile are separated by commas.
For example, the following command combines the functions of 2 NFQUEUE handlers from the previous examples:
insmod /lib/modules/`uname -r`/extra/ipobfs.ko  mark=0x100,0x200 ipp_xor=128,61 data_xor=0x458A2ECD,0x458A2ECD data_xor_offset=4,4 data_xor_len=44,0
It is possible to use different profiles for outgoing and incoming packets.
This will confuse DPI even more by reducing the correlation of in/out streams.
If parameter 'markmask' is set, profile with mask/markmask wins, otherwise mask/mask is searched.
markmask parameter is single for all profiles, no need for commas.
Use markmask if profiles are numerous to not waste single bit for each one.
For example : 0x10/0xf0, 0x20/0xf0, ..., 0xf0/0xf0

By default, the module sets a hook on incoming packets with priority mangle+1, so that the table mangle was already processed
by the time of the call. If non-standard IP protocols arrive at the input, everything is OK. But if there are packets with 
the transport protocol that support checksumming, such as tcp or udp, then modified packets with invalid checksum
will not reach the mangle+1 hook. The module will not receive them.
To solve this problem, specify the pre=raw parameter and do : iptables -t raw -I PREROUTING ...
Outgoing packets can be processed in the usual manner through mangle.

If you need to work with fragmented ipv4 protocols, replace iptables PREROUTING with INPUT (see the remark in the ipobfs section),
specify the module parameter "prehook=input".

Parameters pre,prehook,post,posthook are set individually for each profile and must be comma separated.

The module disables OS-level checksum checking and computing for all processed packets, in some cases
recomputing tcp and udp checksums independently.
If the parameter csum=none, module does not compute checksum at all, allowing sending packets with invalid checksum
before obfuscation. Deobfuscated packets can contain invalid checksum.
If csum=fix, the module takes over the recalculation of the checksum on outgoing packets before the payload is modified,
thereby repeating the functions of the OS or hardware offload. Otherwise OS or hw offload would spoil 2 bytes of data
and after deobfuscation packet would contain incorrect checksum.
If csum=valid, the recalculation of the checksum is done after modifying the payload for both outgoing and incoming packets.
This ensures the visibility of the transmission of packets with a valid checksum.
Checksum correction on the incoming packet is necessary if the device with ipobfs is not the receiver,
but performs the function of a router (forward). So that there is a valid packet on the output interface.
The regular recipient will not accept packets with incorrect checksum.

The debug = 1 parameter enables debugging output. You will see what is done with each processed packet in dmesg.
It should be used only for debugging. With a large number of packets, the system will slow down significantly
due to excessive output in dmesg.

You can view and change some ipobfs parameters without reloading the module : /sys/module/ipobfs/parameters

COMPILING MODULE on traditional linux system :
At first install kernel headers. for debian :
sudo apt-get install linux-headers.....
cd ipobfs_mod
make
sudo make install

SPEED NOTICE
If only ipproto-xor is specified, slowdown is very close to zero.
With data-xor its preferred not to xor offsets after 100-140 bytes.
This way you can avoid linearizing skb's and save lots of cpu time.
debug=1 option can show whether linearizing happens.

openwrt
-------

On a x64 linux system, download and unzip the SDK from your firmware version for your device.
The SDK version must exactly match the firmware version, otherwise you will not build a suitable kernel module.
If you built the firmware yourself, instead of the SDK, you can and should use that buildroot.
scripts/feeds update -a
scripts/feeds install -a
Copy openwrt/* to SDK folder, preserving directory structure.
Copy ipobfs и ipobfs_mod (source code) to packages/ipobfs (the one there openwrt Makefile is).
From SDK root run : make package/ipobfs/compile V=99
Look for 2 ipk : bin/packages/..../ipobfs..ipk и bin/targets/..../kmod-ipobfs..ipk
Copy selected version to the device, install via "opkg install ...ipk".
If reinstalling, first "opkg remove ipobfs" / "opkg remove kmod-ipobfs".

NAT break
------------

In the general case, its safe to assume that NAT can only pass tcp, udp, icmp traffic.
Some NATs also contain helpers for special protocols (GRE). But not all NATs and not on all devices.
NAT can pass non-standard IP protocols, but it does not have the means to track the source IP that initiated
communication. If non-standard protocols work through NAT, then only work for only one device behind NAT.
Using one IP protocol with more than one device behind NAT is not possible. There will be a conflict.
Therefore, ipproto-xor can be used, but carefully.

Consider linux-based NAT (almost all home routers) without helpers.
As the study shows, transport header fields containing payload length and flags are important.
Therefore, the minimum xor-data-offset for tcp is 14, for udp it is 6. Otherwise, the packet will not pass NAT at all.

Any NAT will definitely follow the tcp flags, because conntrack determines the start of the connection.
Conntrack is vital part of any NAT. Flags field offset in tcp header is 13.

Linux conntrack by default verifies transport protocol checksums and does not track packets with invalid checksum.
Such packets do not cause the appearance or change of entries in the conntrack table, the status of packets is INVALID,
SNAT operation will not be applied to them, nevertheless, the forwarding of such packets will still happen unchanged,
maintaining the source address from the internal network. To avoid this behavior, properly configured routers apply
rules like "-m state --state INVALID -j DROP" or "-m conntrack --ctstate INVALID -j DROP", thereby prohibiting forwarding
packets that conntrack refused to account.
This behavior can be changed with the command "sysctl -w net.netfilter.nf_conntrack_checksum=0".
In this case, the checksums will not be considered, conntrack will accept packets even with invalid cheksums, NAT will work.
In openwrt, by default net.netfilter.nf_conntrack_checksum=0, so NAT works with invalid packets.
But other routers usually do not change the default value, which is 1.

Without exception, all NATs will correct the 2-byte checksum in tcp (offset 18) and udp (offset 6) header,
since it is computed using ip source and destination. NAT changes the source ip when sending, source port
can also change. To save resources, a full checksum recalculation is usually not performed.
The initial checksum is taken as a basis, the difference between the initial and changed values​is added to it.
The recipient receives a packet with an invalid checksum, then packet is deobfuscated by ipobfs and checksum becomes
valid again, but only if the initial checksum was not changed during obfuscation, that is,
data-xor-offset> = 20 for tcp and data-xor-offset> = 8 for udp.
The obfuscator XORs, checksum is additive, so they are incompatible.
ipobfs by default does not recalculate the checksums of transport headers, so if it is used at the receiving end, then
data-xor-offset must not cover checksum field, otherwise the packet will be discarded by the system after deobfuscation
As an alternative use --csum=fix option.
ipobfs_mod disables checksums verification, so there is no such problem when using it. default behavior is similar to --csum=fix
If ipproto_xor is used, router will not recalculate the checksum, packet will arrive with invalid checksum after deobfuscation.

Many routers perform mss fix (-j TCPMSS --clamp-mss-to-pmtu or -j TCPMSS --set-mss).
mss is in the tcp header options. Windows and linux send mss as the first option. The option itself takes 4 bytes.
It turns out that the minimum xor-data-offset for tcp rises to 24, because bytes 22-23 can be changed by router.

SUMMARY :
 tcp : data-xor-offset>=24
 udp : data-xor-offset>=8

If NAT doesn’t pass packets with invalid checksums, use --csum=valid option.
In terms of cpu load, it would be preferable not to use the --csum=valid mode if possible.

There is information that some mobile operators terminate tcp on their servers for later proxying to the original
destination. In this case, any tcp modification not at the data flow level is doomed to failure.
A terminating middlebox will reject packets with a corrupted header or invalid checksum.
An outgoing connection from middlebox will not repeat the same packetization as the original connection.
Use obfsproxy.
