#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>

#include "ipv4.h"

void print_ipv4_from_uint32 (unsigned int addr) {
	uint32_bytes *p_addr = (uint32_bytes *) &addr;
	printf ("%d.%d.%d.%d\n", p_addr->byte[0], p_addr->byte[1], 
							 p_addr->byte[2], p_addr->byte[3]);
}


unsigned int reverse_bytes (unsigned int to_reverse) {

	unsigned int reversed;

	uint32_bytes *p_toreverse;
	uint32_bytes *p_reversed;

	p_toreverse = (uint32_bytes *) &to_reverse;
	p_reversed = (uint32_bytes *) &reversed;

	p_reversed->byte[0] = p_toreverse->byte[3];
	p_reversed->byte[1] = p_toreverse->byte[2];
	p_reversed->byte[2] = p_toreverse->byte[1];
	p_reversed->byte[3] = p_toreverse->byte[0];

	return reversed;
}


bool is_broadcast (unsigned int ipv4_addr)
{
	ipv4_addr = reverse_bytes(ipv4_addr);
	return ((ipv4_addr & 0xff) == 0xff);
}


bool is_network (unsigned int ipv4_addr)
{
	ipv4_addr = reverse_bytes(ipv4_addr);
	return ((ipv4_addr & 0xff) == 0x00);
}


/* 
 * function: filter_rb_inc
 * -----------------------
 * find a valid ipv4 address that isn't in a restricted block defined by RFCs
 *
 * ipv4_addr: address to check
 *
 * returns: if the address is valid returns the address,
 * 			otherwise returns a valid address in the next network id
 */
unsigned int filter_rb_inc(unsigned int ipv4_addr)
{
	if ( (RB_224_0_0_0__4) == (ipv4_addr & MASK_CIDR_4) ) {
		ipv4_addr += MAXHOSTS_CIDR_4;
		ipv4_addr &= MASK_CIDR_4;
	}

	if ( (RB_240_0_0_0__4) == (ipv4_addr & MASK_CIDR_4) ) {
		ipv4_addr += MAXHOSTS_CIDR_4;
		ipv4_addr &= MASK_CIDR_4;
	}

	if ( (RB_0_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) || 
		 (RB_10_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) || 
		 (RB_127_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) ) {
		ipv4_addr += MAXHOSTS_CIDR_8;
		ipv4_addr &= MASK_CIDR_8;
	}

	if ( RB_100_64_0_0__10	== (ipv4_addr & MASK_CIDR_10) ) {
		ipv4_addr += MAXHOSTS_CIDR_10;
		ipv4_addr &= MASK_CIDR_10;
	}

	if ( RB_172_16_0_0__12 == (ipv4_addr & MASK_CIDR_12) ) {
		ipv4_addr += MAXHOSTS_CIDR_12;
		ipv4_addr &= MASK_CIDR_12;
	}

	if ( RB_198_18_0_0__15 == (ipv4_addr & MASK_CIDR_15) ) {
		ipv4_addr += MAXHOSTS_CIDR_15;
		ipv4_addr &= MASK_CIDR_15;
	}

	if ( (RB_169_254_0_0__16) == (ipv4_addr & MASK_CIDR_16 ) ||
		 (RB_192_168_0_0__16) == (ipv4_addr & MASK_CIDR_16 )) {
		ipv4_addr += MAXHOSTS_CIDR_16;
		ipv4_addr &= MASK_CIDR_16;	
	}

	if ( (RB_192_0_0_0__24)	== (ipv4_addr & MASK_CIDR_24) ||
	     (RB_192_0_2_0__24) == (ipv4_addr & MASK_CIDR_24) ||
	 	 (RB_192_88_99_0__24) == (ipv4_addr & MASK_CIDR_24) ||
		 (RB_198_51_100_0__24) == (ipv4_addr & MASK_CIDR_24) ||
		 (RB_203_0_113_0__24) == (ipv4_addr & MASK_CIDR_24) ) {
		ipv4_addr += MAXHOSTS_CIDR_24;
		ipv4_addr &= MASK_CIDR_24;
	}

	return ipv4_addr;
}

bool
is_in_rblock(unsigned int ipv4_addr)
{
	bool in_rblock = false;

	if ( (RB_224_0_0_0__4) == (ipv4_addr & MASK_CIDR_4) ) {
		in_rblock = true;
	}

	if ( (RB_240_0_0_0__4) == (ipv4_addr & MASK_CIDR_4) ) {
		in_rblock = true;
	}

	if ( (RB_0_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) || 
		 (RB_10_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) || 
		 (RB_127_0_0_0__8) == (ipv4_addr & MASK_CIDR_8) ) {
		in_rblock = true;
	}

	if ( RB_100_64_0_0__10	== (ipv4_addr & MASK_CIDR_10) ) {
		in_rblock = true;
	}

	if ( RB_172_16_0_0__12 == (ipv4_addr & MASK_CIDR_12) ) {
		in_rblock = true;
	}

	if ( RB_198_18_0_0__15 == (ipv4_addr & MASK_CIDR_15) ) {
		in_rblock = true;
	}

	if ( (RB_169_254_0_0__16) == (ipv4_addr & MASK_CIDR_16 ) ||
		 (RB_192_168_0_0__16) == (ipv4_addr & MASK_CIDR_16 )) {
		in_rblock = true;
	}

	if ( (RB_192_0_0_0__24)	== (ipv4_addr & MASK_CIDR_24) ||
	     (RB_192_0_2_0__24) == (ipv4_addr & MASK_CIDR_24) ||
	 	 (RB_192_88_99_0__24) == (ipv4_addr & MASK_CIDR_24) ||
		 (RB_198_51_100_0__24) == (ipv4_addr & MASK_CIDR_24) ||
		 (RB_203_0_113_0__24) == (ipv4_addr & MASK_CIDR_24) ) {
		in_rblock = true;
	}

	return in_rblock;
}

bool 
is_valid_ipv4_host (unsigned int ipv4_addr)
{
	bool is_host = true;

	if ( is_broadcast(ipv4_addr) )
		is_host = false;

	if ( is_network(ipv4_addr) )
		is_host = false;

/* function in restricted block defined by RFCs are not considered legit */
	if ( is_in_rblock(ipv4_addr) )
		is_host = false;

	return is_host;
}

unsigned int 
filter_valid_ipv4_host (unsigned int ipv4_addr)
{
	ipv4_addr = filter_rb_inc(ipv4_addr);

	if ( is_broadcast(ipv4_addr) )
		ipv4_addr = reverse_bytes (reverse_bytes(ipv4_addr) + 1);
	if ( is_network(ipv4_addr) )
		ipv4_addr = reverse_bytes (reverse_bytes(ipv4_addr) + 1);
	return ipv4_addr;
}
