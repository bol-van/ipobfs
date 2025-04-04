#include "checksum.h"
#include <netinet/in.h>

//#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
//#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

static uint16_t from64to16(uint64_t x)
{
	uint32_t u = (uint32_t)(uint16_t)x + (uint16_t)(x>>16) + (uint16_t)(x>>32) + (uint16_t)(x>>48);
	return (uint16_t)u + (uint16_t)(u>>16);
}

static uint16_t do_csum(const uint8_t * buff, size_t len)
{
	uint8_t odd;
	size_t count;
	uint64_t result,w,carry=0;
	uint16_t u16;

	if (len <= 0) return 0;
	odd = (uint8_t)(1 & (size_t)buff);
	if (odd)
	{
		// any endian compatible
		u16 = 0;
		*((uint8_t*)&u16+1) = *buff;
		result = u16;
		len--;
		buff++;
	}
	else
		result = 0;
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count)
	{
		if (2 & (size_t) buff)
		{
			result += *(uint16_t *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count)
		{
			if (4 & (size_t) buff)
			{
				result += *(uint32_t *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */
			if (count)
			{
				do
				{
					w = *(uint64_t *) buff;
					count--;
					buff += 8;
					result += carry;
					result += w;
					carry = (w > result);
				} while (count);
				result += carry;
				result = (result & 0xffffffff) + (result >> 32);
			}
			if (len & 4)
			{
				result += *(uint32_t *) buff;
				buff += 4;
			}
		}
		if (len & 2)
		{
			result += *(uint16_t *) buff;
			buff += 2;
		}
	}
	if (len & 1)
	{
		// any endian compatible
		u16 = 0;
		*(uint8_t*)&u16 = *buff;
		result += u16;
	}
	u16 = from64to16(result);
	if (odd) u16 = ((u16 >> 8) & 0xff) | ((u16 & 0xff) << 8);
	return u16;
}

uint16_t csum_partial(const void *buff, size_t len)
{
	return do_csum(buff,len);
}

uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr, size_t len, uint8_t proto, uint16_t sum)
{
	return ~from64to16((uint64_t)saddr + daddr + sum + htonl(len+proto));
}

uint16_t ip4_compute_csum(const void *buff, size_t len)
{
	return ~from64to16(do_csum(buff,len));
}
void ip4_fix_checksum(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = ip4_compute_csum(ip, ip->ihl<<2);
}

uint16_t csum_ipv6_magic(const void *saddr, const void *daddr, size_t len, uint8_t proto, uint16_t sum)
{
	uint64_t a = (uint64_t)sum + htonl(len+proto) +
			*(uint32_t*)saddr + *((uint32_t*)saddr+1) + *((uint32_t*)saddr+2) + *((uint32_t*)saddr+3) + 
			*(uint32_t*)daddr + *((uint32_t*)daddr+1) + *((uint32_t*)daddr+2) + *((uint32_t*)daddr+3);
	return ~from64to16(a);
}
