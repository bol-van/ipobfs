#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>

MODULE_DESCRIPTION("ip obfuscator. xor ip protocol or data payload with some values. supports multiple profiles triggered by fwmark bits");
MODULE_AUTHOR("bol-van");
MODULE_LICENSE("GPL");

#define MAX_MARK	32

typedef enum
{
	none=0,fix,valid
} t_csum;
static t_csum csum[MAX_MARK];
static int ct_csum;

static bool debug=false;
static uint mark[MAX_MARK], markmask=0;
static int ct_mark=0;
static uint data_xor[MAX_MARK];
static int ct_data_xor=0;
static uint data_xor_offset[MAX_MARK];
static int ct_data_xor_offset=0;
static uint data_xor_len[MAX_MARK];
static int ct_data_xor_len=0;
static ushort ipp_xor[MAX_MARK];
static int ct_ipp_xor=0;

static char *prehook_s[MAX_MARK];
static unsigned int prehook[MAX_MARK];
static int ct_prehook;
static char *pre_s[MAX_MARK];
static int pre[MAX_MARK];
static int ct_pre;
static char *posthook_s[MAX_MARK];
static unsigned int posthook[MAX_MARK];
static int ct_posthook;
static char *post_s[MAX_MARK];
static int post[MAX_MARK];
static int ct_post;
static char *csum_s[MAX_MARK];

module_param(debug,bool,0640);

module_param_array(mark,uint,&ct_mark,0640);
module_param(markmask,uint,0640);

module_param_array(data_xor,uint,&ct_data_xor,0640);
module_param_array(data_xor_offset,uint,&ct_data_xor_offset,0640);
module_param_array(data_xor_len,uint,&ct_data_xor_len,0640);
module_param_array(ipp_xor,ushort,&ct_ipp_xor,0640);

module_param_array_named(prehook,prehook_s,charp,&ct_prehook,0440);
module_param_array_named(pre,pre_s,charp,&ct_pre,0440);
module_param_array_named(posthook,posthook_s,charp,&ct_posthook,0440);
module_param_array_named(post,post_s,charp,&ct_post,0440);

module_param_array_named(csum,csum_s,charp,&ct_csum,0440);

MODULE_PARM_DESC(debug, "printk debug info");
MODULE_PARM_DESC(mark, "fwmark filters : 0x100,0x200,0x400. if markmask not specified, markmask=mark for each profile");
MODULE_PARM_DESC(markmask, "fwmark filter mask : common mask for all profiles. if not specified, markmask=mark for each profile");
MODULE_PARM_DESC(data_xor, "uint32 data xor : 0xDEADBEAF,0x01020304,0");
MODULE_PARM_DESC(data_xor_offset, "start xoring from position : 4,4,8");
MODULE_PARM_DESC(data_xor_len, "xor no more than : 0,0,16");
MODULE_PARM_DESC(ipp_xor, "xor ip protocol with : 0,0x80,42");
MODULE_PARM_DESC(prehook, "input hook : none, prerouting (default), input, forward");
MODULE_PARM_DESC(pre, "input hook priority : mangle (default), raw, filter or <integer>");
MODULE_PARM_DESC(posthook, "output hook : none, postrouting (default), output, forward");
MODULE_PARM_DESC(post, "output hook priority : mangle (default), raw, filter or <integer>");
MODULE_PARM_DESC(csum, "csum mode : none = invalid csums are ok, fix = valid csums on original outgoing packets, valid = valid csums on obfuscated packets");


#define GET_PARAM(name,idx) (idx<ct_##name ? name[idx] : 0)
#define GET_DATA_XOR_LEN(idx) (GET_PARAM(data_xor_len,idx) ? GET_PARAM(data_xor_len,idx) : 0xFFFF)

typedef struct {
	int priority;
	bool bOutgoing;
} t_hook_id;



static int nf_priority_from_string(const char *s)
{
	int r,n = NF_IP_PRI_MANGLE+1;
	if (s)
	{
		if (!strcmp(s,"mangle"))
			n = NF_IP_PRI_MANGLE+1;
		else if (!strcmp(s,"raw"))
			n = NF_IP_PRI_RAW+1;
		else if (!strcmp(s,"filter"))
			n = NF_IP_PRI_FILTER+1;
		else
			r = kstrtoint(s, 0, &n);
	}
	return n;
}
static const char *nf_string_from_priority(int pri)
{
	switch(pri)
	{
		case NF_IP_PRI_RAW+1: return "raw";
		case NF_IP_PRI_MANGLE+1: return "mangle";
		case NF_IP_PRI_FILTER+1: return "filter";
		default: return "custom";
	}
}
static unsigned int nf_hooknum_from_string(const char *s, int def_num)
{
	int r,n = def_num;
	if (s)
	{
		if (!strcmp(s,"input"))
			n = NF_INET_LOCAL_IN;
		else if (!strcmp(s,"forward"))
			n = NF_INET_FORWARD;
		else if (!strcmp(s,"output"))
			n = NF_INET_LOCAL_OUT;
		else if (!strcmp(s,"postrouting"))
			n = NF_INET_POST_ROUTING;
		else if (!strcmp(s,"prerouting"))
			n = NF_INET_PRE_ROUTING;
		else if (!strcmp(s,"none"))
			n = -1;
		else
			r = kstrtoint(s, 0, &n);
	}
	return n;
}
static const char *nf_string_from_hooknum(int hooknum)
{
	switch(hooknum)
	{
		case NF_INET_PRE_ROUTING: return "prerouting";
		case NF_INET_POST_ROUTING: return "postrouting";
		case NF_INET_LOCAL_IN: return "input";
		case NF_INET_LOCAL_OUT: return "output";
		case NF_INET_FORWARD: return "forward";
		case -1: return "none";
		default: return "custom";
	}
}
static t_csum csum_from_string(char *s)
{
	t_csum m;
	if (!s) m=none;
	else if (!strcmp(s,"fix")) m=fix;
	else if (!strcmp(s,"valid")) m=valid;
	else m=none;
	return m;
}
static const char *string_from_csum(t_csum csum)
{
	switch(csum)
	{
		case fix: return "fix";
		case valid: return "valid";
		default: return "none";
	}
}
static void translate_csum_s(void)
{
	int i;
	for(i=0;i<ct_csum;i++) csum[i]=csum_from_string(csum_s[i]);
}
static void translate_hooknum(char **hooknum_s, int ct, unsigned int *hooknum, int def_hooknum)
{
	int i;
	for(i=0;i<ct_mark;i++) hooknum[i] = nf_hooknum_from_string(i<ct ? hooknum_s[i] : NULL, def_hooknum);
}
static void translate_priority(char **pri_s, int ct, int *pri)
{
	int i;
	for(i=0;i<ct_mark;i++) pri[i] = nf_priority_from_string(i<ct ? pri_s[i] : NULL);
}


static int find_mark(uint fwmark)
{
	int i;
	if (markmask)
	{
		uint m = fwmark & markmask;
		for(i=0;i<ct_mark;i++)
			if (m == mark[i]) return i;
	}
	else
	{
		for(i=0;i<ct_mark;i++)
			if (fwmark & mark[i]) return i;
	}
	return -1;
}


static void ip4_fix_checksum(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = ip_fast_csum(ip,ip->ihl);
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

static u8 ip_proto_ver(const void *net_header)
{
	return (*(u8*)net_header)>>4;
}
static u8 transport_proto(const void *net_header)
{
	switch(ip_proto_ver(net_header))
	{
		case 4:
			return ((struct iphdr*)net_header)->protocol;
		case 6:
			return ((struct ipv6hdr*)net_header)->nexthdr;
		default:
			return 0;
	}
}

static void fix_transport_checksum(struct sk_buff *skb)
{
	uint tlen;
	u8 *pn, *pt, pver, proto;
	__sum16 check=0, check_old;

	if (!skb_transport_header_was_set(skb)) return;

	pn = skb_network_header(skb);
	pver = ip_proto_ver(pn);
	if (pver==4 && ip4_fragmented((struct iphdr*)pn))
	{
		if (debug) printk(KERN_DEBUG "ipobfs: fix_transport_checksum not fixing checksum in fragmented ip\n");
		return; // no way we can compute valid checksum for ip fragment
	}
	proto = transport_proto(pn);
	pt = skb_transport_header(skb);
	tlen = skb_headlen(skb) - (skb->transport_header - skb->network_header);
	switch(proto)
	{
		case IPPROTO_TCP :
			if (tlen<sizeof(struct tcphdr)) return;
			check_old = ((struct tcphdr*)pt)->check;
			((struct tcphdr*)pt)->check = 0;
			break;
		case IPPROTO_UDP:
			if (tlen<sizeof(struct udphdr)) return;
			check_old = ((struct udphdr*)pt)->check;
			((struct udphdr*)pt)->check = 0;
			break;
		default:
			return;
	}
	switch(pver)
	{
		case 4:
			check = csum_tcpudp_magic(((struct iphdr*)pn)->saddr, ((struct iphdr*)pn)->daddr, tlen, proto, csum_partial(pt, tlen, 0));
			break;
		case 6:
			check = csum_ipv6_magic(&((struct ipv6hdr*)pn)->saddr, &((struct ipv6hdr*)pn)->daddr, tlen, proto, csum_partial(pt, tlen, 0));
			break;
	}
	switch(proto)
	{
		case IPPROTO_TCP:
			((struct tcphdr*)pt)->check = check;
			break;
		case IPPROTO_UDP:
			((struct udphdr*)pt)->check = check;
			break;
	}
	if (debug) printk(KERN_DEBUG "ipobfs: fix_transport_checksum pver=%u proto=%u tlen=%u %04X => %04X\n",pver,proto,tlen,check_old,check);
}



static u32 rotr32 (u32 value, uint count)
{
	return value >> count | value << (32 - count);
}
static u32 rotl32 (u32 value, uint count)
{
	return value << count | value >> (32 - count);
}
// this function can xor multi-chunked payload. data point to a chunk, len means chunk length, data_pos tells byte offset of this chunk
// on some architectures misaligned access cause exception , kernel transparently fixes it, but it costs huge slowdown - 15-20 times slower
static void modify_packet_payload(u8 *data,uint len,uint data_pos, u32 data_xor, uint data_xor_offset, uint data_xor_len)
{
	if (data_xor_offset<(data_pos+len) && (data_xor_offset+data_xor_len)>data_pos)
	{
		uint start=data_xor_offset>data_pos ? data_xor_offset-data_pos : 0;
		if (start<len)
		{
			uint end = ((data_xor_offset+data_xor_len)<(data_pos+len)) ? data_xor_offset+data_xor_len-data_pos : len;
			u32 xor,n;
			len = end-start;
			data += start;
			xor = data_xor;
			n = (4-((data_pos+start)&3))&3;
			if (n) xor=rotr32(xor,n<<3);
			while(len && ((size_t)data & 7))
			{
				*data++ ^= (u8)(xor=rotl32(xor,8));
				len--;
			}
			{
				register u64 nxor=htonl(xor);
				nxor = (nxor<<32) | nxor;
				for( ; len>=8 ; len-=8,data+=8) *(u64*)data ^= nxor;
				if (len>=4)
				{
					*(u32*)data ^= (u32)nxor;
					len-=4; data+=4;
				}
			}
			while(len--) *data++ ^= (u8)(xor=rotl32(xor,8));
		}
	}
}
static void modify_skb_payload(struct sk_buff *skb,int idx,bool bOutgoing)
{
	uint len;
	u8 *p,*pn,pver;
	t_csum csum_mode;

	if (!skb_transport_header_was_set(skb)) return;

	len = skb_headlen(skb);
	p = skb_transport_header(skb);
	len -= skb->transport_header - skb->network_header;
	csum_mode=GET_PARAM(csum,idx);

	// dont linearize if possible
	if (skb_is_nonlinear(skb))
	{
		uint last_mod_offset=GET_PARAM(data_xor_offset,idx)+GET_DATA_XOR_LEN(idx);
		if(csum_mode==fix || csum_mode==valid || last_mod_offset>len)
		{
			if (debug) printk(KERN_DEBUG "ipobfs: nonlinear skb. skb_headlen=%u skb_data_len=%u skb_len_transport=%u last_mod_offset=%u csum_mode=%s. linearize skb",skb_headlen(skb),skb->data_len,len,last_mod_offset,string_from_csum(csum_mode));
			if (skb_linearize(skb)) 
			{
				if (debug) printk(KERN_DEBUG "ipobfs: failed to linearize skb");
				return;
			}
			len = skb_headlen(skb);
			p = skb_transport_header(skb);
			len -= skb->transport_header - skb->network_header;
		}
		else
			if (debug) printk(KERN_DEBUG "ipobfs: nonlinear skb. skb_headlen=%u skb_data_len=%u skb_len_transport=%u last_mod_offset=%u csum_mode=%s. dont linearize skb",skb_headlen(skb),skb->data_len,len,last_mod_offset,string_from_csum(csum_mode));
	}

	if (bOutgoing && csum_mode==fix) fix_transport_checksum(skb);

	pn = skb_network_header(skb);
	pver = ip_proto_ver(pn);
	modify_packet_payload(p,len,pver==4 ? ip4_frag_offset((struct iphdr*)pn) : 0, GET_PARAM(data_xor,idx), GET_PARAM(data_xor_offset,idx), GET_DATA_XOR_LEN(idx));

	if (debug) printk(KERN_DEBUG "ipobfs: modify_skb_payload ipv%u proto=%u len=%u data_xor=%08X data_xor_offset=%u data_xor_len=%u\n",pver,transport_proto(pn),len,GET_PARAM(data_xor,idx), GET_PARAM(data_xor_offset,idx), GET_DATA_XOR_LEN(idx));
	if (csum_mode==valid) fix_transport_checksum(skb);
}

static void fix_skb_csum(struct sk_buff *skb,int idx,bool bOutgoing)
{
	t_csum csum_mode=GET_PARAM(csum,idx);
	if (csum_mode==valid || (bOutgoing && csum_mode==fix)) fix_transport_checksum(skb);
}


static void modify_skb_ipp(struct sk_buff *skb,int idx)
{
	uint8_t pver,proto_old=0,proto_new=0;
	switch(pver = ip_proto_ver(skb_network_header(skb)))
	{
		case 4:
		{
			struct iphdr *ip = ip_hdr(skb);
			proto_old = ip->protocol;
			proto_new = ip->protocol ^= (u8)GET_PARAM(ipp_xor,idx);
			ip4_fix_checksum(ip);
			break;
		}
		case 6:
		{
			struct ipv6hdr *ip6 = ipv6_hdr(skb);
			proto_old = ip6->nexthdr;
			proto_new = ip6->nexthdr ^= (u8)GET_PARAM(ipp_xor,idx);
			break;
		}
	}
	if (debug) printk(KERN_DEBUG "ipobfs: modify_skb_ipp pver=%u proto %u=>%u\n",pver,proto_old,proto_new);
}

static uint hook_ip(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int idx = find_mark(skb->mark);
	if (idx!=-1)
	{
		bool bOutgoing = ((t_hook_id*)priv)->bOutgoing;
		if (debug)
			printk(KERN_DEBUG "ipobfs: hook_ip %s mark_idx=%d hook=%s pri=%s in=%s out=%s\n",
				bOutgoing ? "out" : "in",
				idx,
				nf_string_from_hooknum(state->hook),
				nf_string_from_priority(((t_hook_id*)priv)->priority),
				state->in ? state->in->name : "null", state->out ? state->out->name : "null");
		if ((!bOutgoing && ((t_hook_id*)priv)->priority==pre[idx] && state->hook==prehook[idx]) ||
			(bOutgoing && ((t_hook_id*)priv)->priority==post[idx] && state->hook==posthook[idx]))
		{
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			// do data modification with original ip protocol. necessary for checksums
			if (bOutgoing)
			{
				if (GET_PARAM(data_xor,idx))
					modify_skb_payload(skb,idx,bOutgoing);
				if (GET_PARAM(ipp_xor,idx))
				{
					if (!GET_PARAM(data_xor,idx))
						// if we make it not tcp/udp, offload will not calc csum. must take care of this.
						fix_skb_csum(skb,idx,bOutgoing);
					modify_skb_ipp(skb,idx);
				}
			}
			else
			{
				if (GET_PARAM(ipp_xor,idx)) modify_skb_ipp(skb,idx);
				if (GET_PARAM(data_xor,idx)) modify_skb_payload(skb,idx,bOutgoing);
			}
			// clear mask bits to avoid processing in post hook
			skb->mark &= ~(markmask ? markmask : GET_PARAM(mark,idx));
		}
	}
	return NF_ACCEPT;
}





static struct nf_hook_ops nfhk_pre[MAX_MARK*2], nfhk_post[MAX_MARK*2];
static int ct_nfhk_pre,ct_nfhk_post;
static t_hook_id hookid_pre[MAX_MARK],hookid_post[MAX_MARK];

static int find_hook(const struct nf_hook_ops *nfhk, int ct,  unsigned int hooknum, int priority, u8 pf)
{
	int i;
	for(i=0;i<ct;i++)
		if (nfhk[i].hooknum==hooknum && nfhk[i].priority==priority && nfhk[i].pf==pf)
			return i;
	return -1;
}
static void fill_hook_table(struct nf_hook_ops *nfhk, int *ct, t_hook_id *hookid, unsigned int *hooknums, int *pris, bool bOutgoing)
{
	int i, n;

	*ct = 0;
	for(i=n=0;i<ct_mark;i++)
	{
		if (hooknums[i]!=-1 && find_hook(nfhk,*ct,hooknums[i],pris[i],PF_INET)==-1)
		{
			hookid[n].priority = pris[i];
			hookid[n].bOutgoing = bOutgoing;

			nfhk[*ct].hook = hook_ip;
			nfhk[*ct].hooknum = hooknums[i];
			nfhk[*ct].priority = pris[i];
			nfhk[*ct].priv = hookid+n;
			nfhk[*ct].pf = PF_INET;

			nfhk[*ct+1] = nfhk[*ct];
			nfhk[*ct+1].pf = PF_INET6;

			*ct+=2;
			n++;
		}
	}
}
static void printk_hook_table(const char *prefix, const struct nf_hook_ops *nfhk, int ct)
{
	int i;
	printk(KERN_INFO "ipobfs: registered %s hooks:\n",prefix);
	for(i=0;i<ct;i++)
	{
		if (nfhk[i].pf==PF_INET)
			printk(KERN_INFO "ipobfs:  hook=%s(%d) priority=%s(%d)\n",
				nf_string_from_hooknum(nfhk[i].hooknum),nfhk[i].hooknum,
				nf_string_from_priority(nfhk[i].priority),nfhk[i].priority);
	}
}
 
int init_module(void)
{
	int i;

	if (!ct_mark)
	{
		printk(KERN_ERR "ipobfs: this module requires parameters. at least one profile is required. use 'mark' parameter\n");
		return -EINVAL;
	}

	translate_csum_s();
	translate_hooknum(prehook_s,ct_prehook,prehook,NF_INET_PRE_ROUTING);
	translate_priority(pre_s,ct_pre,pre);
	translate_hooknum(posthook_s,ct_posthook,posthook,NF_INET_POST_ROUTING);
	translate_priority(post_s,ct_post,post);

	printk(KERN_INFO "ipobfs: module loaded : debug=%d ct_mark=%d markmask=%08X ct_ipp_xor=%d ct_data_xor=%d ct_data_xor_offset=%d ct_csum=%d\n",
		debug,ct_mark,markmask,ct_ipp_xor,ct_data_xor,ct_data_xor_offset,ct_csum);
	for (i=0;i<ct_mark;i++) printk(KERN_INFO "ipobfs: mark 0x%08X/0x%08X : ipp_xor=%u(0x%02X) data_xor=0x%08X data_xor_offset=%u data_xor_len=%u csum=%s prehook=%s(%d) pre=%s(%d) posthook=%s(%d) post=%s(%d)\n",
		GET_PARAM(mark,i),markmask ? markmask : GET_PARAM(mark,i),
		GET_PARAM(ipp_xor,i),GET_PARAM(ipp_xor,i),GET_PARAM(data_xor,i),GET_PARAM(data_xor_offset,i),GET_PARAM(data_xor_len,i),
		string_from_csum(GET_PARAM(csum,i)),
		nf_string_from_hooknum(prehook[i]),prehook[i],
		nf_string_from_priority(pre[i]),pre[i],
		nf_string_from_hooknum(posthook[i]),posthook[i],
		nf_string_from_priority(post[i]),post[i]);

	fill_hook_table(nfhk_pre,&ct_nfhk_pre,hookid_pre,prehook,pre,false);
	i = nf_register_net_hooks(&init_net,nfhk_pre,ct_nfhk_pre);
	if (i)
	{
		printk(KERN_ERR "ipobfs: could not register netfilter pre hooks. err=%d\n",i);
		return i;
	}
	fill_hook_table(nfhk_post,&ct_nfhk_post,hookid_post,posthook,post,true);
	i = nf_register_net_hooks(&init_net,nfhk_post,ct_nfhk_post);
	if (i)
	{
		nf_unregister_net_hooks(&init_net,nfhk_pre,ct_nfhk_pre);
		printk(KERN_ERR "ipobfs: could not register netfilter post hooks. err=%d\n",i);
		return i;
	}
	printk_hook_table("pre",nfhk_pre,ct_nfhk_pre);
	printk_hook_table("post",nfhk_post,ct_nfhk_post);

	return 0;
}

void cleanup_module(void)
{
	nf_unregister_net_hooks(&init_net,nfhk_pre,ct_nfhk_pre);
	nf_unregister_net_hooks(&init_net,nfhk_post,ct_nfhk_post);
	printk(KERN_INFO "ipobfs: module unloaded\n");
}
