#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <time.h>
#include "checksum.h"

#define NF_DROP 0
#define NF_ACCEPT 1



typedef enum
{
	none = 0, fix, valid
} csum_mode;

struct params_s
{
	bool debug;
	csum_mode csum;
	int qnum;
	uint8_t ipp_xor;
	uint32_t data_xor;
	size_t data_xor_offset, data_xor_len;
};

struct params_s params;


static bool proto_check_ipv4(uint8_t *data, size_t len)
{
	return 	len >= 20 && (data[0] & 0xF0) == 0x40 &&
		len >= ((data[0] & 0x0F) << 2);
}
// move to transport protocol
static void proto_skip_ipv4(uint8_t **data, size_t *len)
{
	size_t l;

	l = (**data & 0x0F) << 2;
	*data += l;
	*len -= l;
}

static bool proto_check_ipv6(uint8_t *data, size_t len)
{
	return 	len >= 40 && (data[0] & 0xF0) == 0x60 &&
		(len - 40) >= htons(*(uint16_t*)(data + 4)); // payload length
}
static void proto_skip_ipv6_base_header(uint8_t **data, size_t *len)
{
	*data += 40; *len -= 40; // skip ipv6 base header
}


static bool ip4_fragmented(struct iphdr *ip)
{
	// fragment_offset!=0 or more fragments flag
	return !!(ntohs(ip->frag_off) & 0x3FFF);
}
static uint16_t ip4_frag_offset(struct iphdr *ip)
{
	return (ntohs(ip->frag_off) & 0x1FFF)<<3;
}


static void fix_transport_checksum(struct iphdr *ip, struct ip6_hdr *ip6, uint8_t *tdata, size_t tlen)
{
	uint8_t proto;
	uint16_t check, check_old;

	if (!!ip == !!ip6) return; // must be only one

	if (ip && ip4_fragmented(ip))
	{
		if (params.debug) printf("fix_transport_checksum not fixing checksum in fragmented ip\n");
		return; // no way we can compute valid checksum for ip fragment
	}

	proto = ip ? ip->protocol : ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	switch (proto)
	{
	case IPPROTO_TCP:
		if (tlen < sizeof(struct tcphdr)) return;
		check_old = ((struct tcphdr*)tdata)->check;
		((struct tcphdr*)tdata)->check = 0;
		break;
	case IPPROTO_UDP:
		if (tlen < sizeof(struct udphdr)) return;
		check_old = ((struct udphdr*)tdata)->check;
		((struct udphdr*)tdata)->check = 0;
		break;
	default:
		return;
	}
	check = ip ? csum_tcpudp_magic(ip->saddr,ip->daddr,tlen,proto,csum_partial(tdata, tlen)) : csum_ipv6_magic(&ip6->ip6_src,&ip6->ip6_dst,tlen,proto,csum_partial(tdata, tlen));
	switch (proto)
	{
	case IPPROTO_TCP:
		((struct tcphdr*)tdata)->check = check;
		break;
	case IPPROTO_UDP:
		((struct udphdr*)tdata)->check = check;
		break;
	}
	if (params.debug) printf("fix_transport_checksum pver=%c proto=%u %04X => %04X\n", ip ? '4' : '6', proto, check_old, check);

}


static uint32_t rotl32(uint32_t value, unsigned int count)
{
	return value << count | value >> (32 - count);
}
static uint32_t rotr32 (uint32_t value, unsigned int count)
{
	return value >> count | value << (32 - count);
}
// this function can xor multi-chunked payload. data point to a chunk, len means chunk length, data_pos tells byte offset of this chunk
// on some architectures misaligned access cause exception , kernel transparently fixes it, but it costs huge slowdown - 15-20 times slower
static void _modify_packet_payload(uint8_t *data,size_t len,size_t data_pos, uint32_t data_xor, size_t data_xor_offset, size_t data_xor_len)
{
	if (!data_xor_len) data_xor_len=0xFFFF;
	if (data_xor_offset<(data_pos+len) && (data_xor_offset+data_xor_len)>data_pos)
	{
		size_t start=data_xor_offset>data_pos ? data_xor_offset-data_pos : 0;
		if (start<len)
		{
			size_t end = ((data_xor_offset+data_xor_len)<(data_pos+len)) ? data_xor_offset+data_xor_len-data_pos : len;
			uint32_t xor,n;
			len = end-start;
			data += start;
			xor = data_xor;
			n = (4-((data_pos+start)&3))&3;
			if (n) xor=rotr32(xor,n<<3);
			while(len && ((size_t)data & 7))
			{
				*data++ ^= (uint8_t)(xor=rotl32(xor,8));
				len--;
			}
			{
				register uint64_t nxor=htonl(xor);
				nxor = (nxor<<32) | nxor;
				for( ; len>=8 ; len-=8,data+=8) *(uint64_t*)data ^= nxor;
				if (len>=4)
				{
					*(uint32_t*)data ^= (uint32_t)nxor;
					len-=4; data+=4;
				}
			}
			while(len--) *data++ ^= (uint8_t)(xor=rotl32(xor,8));
		}
	}
}
static void modify_packet_payload(struct iphdr *ip, struct ip6_hdr *ip6, uint8_t *tdata, size_t tlen, int indev, int outdev)
{
	if (tlen > params.data_xor_offset)
	{
		if (params.debug) printf("modify_packet_payload data_xor %08X\n", params.data_xor);

		_modify_packet_payload(tdata,tlen, ip ? ip4_frag_offset(ip) : 0,params.data_xor,params.data_xor_offset,params.data_xor_len);

		// incoming packets : we cant disable sum check in kernel. instead we forcibly make checksum valid
		// if indev==0 it means packet was locally generated. no need to fix checksum because its supposed to be valid
		if ((params.csum == valid || params.csum == fix && indev)) fix_transport_checksum(ip, ip6, tdata, tlen);
	}
}


static bool modify_ip4_packet(uint8_t *data, size_t len, int indev, int outdev)
{
	bool bRes = false;
	uint8_t bOutgoing=!indev;
	struct iphdr *iphdr = (struct iphdr*)data;

	// do data modification with original ip protocol. necessary for checksums
	for(uint8_t b=0;b<=1;b++)
	{
		if (params.data_xor && b!=bOutgoing)
		{
			uint8_t *tdata = data;
			size_t tlen = len;
			proto_skip_ipv4(&tdata, &tlen);
			modify_packet_payload(iphdr, NULL, tdata, tlen, indev, outdev);
			bRes = true;
		}
		if (params.ipp_xor && b==bOutgoing)
		{
			uint8_t proto = iphdr->protocol;
			iphdr->protocol ^= params.ipp_xor;
			if (params.debug) printf("modify_ipv4_packet proto %u=>%u\n", proto, iphdr->protocol);
			ip4_fix_checksum(iphdr);
			bRes = true;
		}
	}
	return bRes;
}
static bool modify_ip6_packet(uint8_t *data, size_t len, int indev, int outdev)
{
	bool bRes = false;
	uint8_t bOutgoing=!indev;
	struct ip6_hdr *ip6hdr = (struct ip6_hdr*)data;

	// do data modification with original ip protocol. necessary for checksums
	for(uint8_t b=0;b<=1;b++)
	{
		if (params.data_xor && b!=bOutgoing)
		{
			uint8_t *tdata = data;
			size_t tlen = len;
			proto_skip_ipv6_base_header(&tdata, &tlen);
			modify_packet_payload(NULL, ip6hdr, tdata, tlen, indev, outdev);
			bRes = true;
		}
		if (params.ipp_xor && b==bOutgoing)
		{
			uint8_t proto = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt ^= params.ipp_xor;
			if (params.debug) printf("modify_ipv6_packet proto %u=>%u\n", proto, ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
			bRes = true;
		}
	}
	return bRes;
}


typedef enum
{
	pass = 0, modify, drop
} packet_process_result;
static packet_process_result processPacketData(uint8_t *data_pkt, size_t len_pkt, int indev, int outdev)
{
	struct iphdr *iphdr = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	bool bMod = false;

	if (proto_check_ipv4(data_pkt, len_pkt))
		bMod = modify_ip4_packet(data_pkt, len_pkt, indev, outdev);
	else if (proto_check_ipv6(data_pkt, len_pkt))
		bMod = modify_ip6_packet(data_pkt, len_pkt, indev, outdev);
	return bMod ? modify : pass;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *cookie)
{
	__be32 id;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	len = nfq_get_payload(nfa, &data);
	if (params.debug) printf("packet: id=%d len=%zu\n", id, len);
	if (len >= 0)
	{
		switch (processPacketData(data, len, nfq_get_indev(nfa), nfq_get_outdev(nfa)))
		{
		case modify: return nfq_set_verdict(qh, id, NF_ACCEPT, len, data);
		case drop: return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static bool setpcap(cap_value_t *caps, int ncaps)
{
	cap_t capabilities;

	if (!(capabilities = cap_init()))
		return false;

	if (ncaps && (cap_set_flag(capabilities, CAP_PERMITTED, ncaps, caps, CAP_SET) ||
		cap_set_flag(capabilities, CAP_EFFECTIVE, ncaps, caps, CAP_SET)))
	{
		cap_free(capabilities);
		return false;
	}
	if (cap_set_proc(capabilities))
	{
		cap_free(capabilities);
		return false;
	}
	cap_free(capabilities);
	return true;
}
static int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap", "r");
	if (F)
	{
		int n = fscanf(F, "%d", &maxcap);
		fclose(F);
	}
	return maxcap;

}
static bool dropcaps()
{
	// must have CAP_SETPCAP at the end. its required to clear bounding set
	cap_value_t cap_values[] = { CAP_NET_ADMIN,CAP_SETPCAP };
	int capct = sizeof(cap_values) / sizeof(*cap_values);
	int maxcap = getmaxcap();

	if (setpcap(cap_values, capct))
	{
		for (int cap = 0; cap <= maxcap; cap++)
		{
			if (cap_drop_bound(cap))
			{
				fprintf(stderr, "could not drop cap %d\n", cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(cap_values, capct - 1))
	{
		perror("setpcap");
		return false;
	}
	return true;
}
static bool droproot(uid_t uid, gid_t gid)
{
	if (uid || gid)
	{
		if (prctl(PR_SET_KEEPCAPS, 1L))
		{
			perror("prctl(PR_SET_KEEPCAPS): ");
			return false;
		}
		if (setgid(gid))
		{
			perror("setgid: ");
			return false;
		}
		if (setuid(uid))
		{
			perror("setuid: ");
			return false;
		}
	}
	return dropcaps();
}

static void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	int fd;
	/* stdin */
	fd = dup(0);
	/* stdout */
	fd = dup(0);
	/* stderror */
}

static bool writepid(const char *filename)
{
	FILE *F;
	if (!(F = fopen(filename, "w")))
		return false;
	fprintf(F, "%d", getpid());
	fclose(F);
	return true;
}


static void exithelp()
{
	printf(
		" --qnum=<nfqueue_number>\n"
		" --daemon\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t; write pid to file\n"
		" --user=<username>\t\t; drop root privs\n"
		" --debug\t\t\t; print debug info\n"
		" --uid=uid[:gid]\t\t; drop root privs\n"
		" --ipproto-xor=0..255|0x00-0xFF\t; xor protocol ID with given value\n"
		" --data-xor=0xDEADBEAF\t\t; xor IP payload (after IP header) with 32-bit HEX value\n"
		" --data-xor-offset=<position>\t; start xoring at specified position after IP header end\n"
		" --data-xor-len=<bytes>\t\t; xor block max length. xor entire packet after offset if not specified\n"
		" --csum=none|fix|valid\t\t; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid\n"
	);
	exit(1);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[16384] __attribute__((aligned));
	int option_index = 0;
	int v;
	bool daemon = false;
	uid_t uid = 0;
	gid_t gid = 0;
	char pidfile[256];

	srand(time(NULL));

	memset(&params, 0, sizeof(params));
	params.data_xor_len = 0xFFFF;
	*pidfile = 0;

	const struct option long_options[] = {
		{"qnum",required_argument,0,0},	// optidx=0
		{"daemon",no_argument,0,0},		// optidx=1
		{"pidfile",required_argument,0,0},	// optidx=2
		{"user",required_argument,0,0 },// optidx=3
		{"uid",required_argument,0,0 },// optidx=4
		{"debug",no_argument,0,0 },// optidx=5
		{"ipproto-xor",required_argument,0,0},	// optidx=6
		{"data-xor",required_argument,0,0},	// optidx=7
		{"data-xor-offset",required_argument,0,0},	// optidx=8
		{"data-xor-len",required_argument,0,0},	// optidx=9
		{"csum",required_argument,0,0},	// optidx=10
		{NULL,0,NULL,0}
	};
	if (argc < 2) exithelp();
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* qnum */
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				fprintf(stderr, "bad qnum\n");
				exit(1);
			}
			break;
		case 1: /* daemon */
			daemon = true;
			break;
		case 2: /* pidfile */
			strncpy(pidfile, optarg, sizeof(pidfile));
			pidfile[sizeof(pidfile) - 1] = '\0';
			break;
		case 3: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit(1);
			}
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			break;
		}
		case 4: /* uid */
			gid = 0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg, "%u:%u", &uid, &gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit(1);
			}
			break;
		case 5: /* debug */
			params.debug = true;
			break;
		case 6: /* ipproto-xor */
		{
			uint u;
			if (!sscanf(optarg, "0x%X", &u) && !sscanf(optarg, "%u", &u) || u > 255)
			{
				fprintf(stderr, "ipp-xor should be 1-byte decimal or 0x<HEX>\n");
				exit(1);
			}
			params.ipp_xor = (uint8_t)u;
		}
		break;
		case 7: /* data-xor */
			if (!sscanf(optarg, "0x%X", &params.data_xor))
			{
				fprintf(stderr, "data-xor should be 32 bit HEX starting with 0x\n");
				exit(1);
			}
			break;
		case 8: /* data-xor-offset */
			params.data_xor_offset = (size_t)atoi(optarg);
			break;
		case 9: /* data-xor-len */
			params.data_xor_len = (size_t)atoi(optarg);
			break;
		case 10: /* csum */
			if (!strcmp(optarg, "none"))
				params.csum = none;
			else if (!strcmp(optarg, "fix"))
				params.csum = fix;
			else if (!strcmp(optarg, "valid"))
				params.csum = valid;
			else
			{
				fprintf(stderr, "invalid csum parameter\n");
				exit(1);
			}
			break;
		}
	}

	if (daemon) daemonize();

	h = NULL;
	qh = NULL;

	if (*pidfile && !writepid(pidfile))
	{
		fprintf(stderr, "could not write pidfile\n");
		goto exiterr;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		goto exiterr;
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		goto exiterr;
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		goto exiterr;
	}

	printf("binding this socket to queue '%u'\n", params.qnum);
	qh = nfq_create_queue(h, params.qnum, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		goto exiterr;
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		goto exiterr;
	}

	if (!droproot(uid, gid)) goto exiterr;
	fprintf(stderr, "Running as UID=%u GID=%u\n", getuid(), getgid());

	fd = nfq_fd(h);
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
	{
		int r = nfq_handle_packet(h, buf, rv);
		if (r) fprintf(stderr, "nfq_handle_packet error %d\n", r);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	return 0;

exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	return 1;
}
