#ifndef GENERATOR_HEADER
#define GENERATOR_HEADER

#include "bool.h"

/* AND MASK to get network part of an adress in integer format */
#define 		MASK_CIDR_4					0x000000F0
#define 		MASK_CIDR_8					0x000000FF
#define			MASK_CIDR_10				0x0000C0FF
#define 		MASK_CIDR_12				0x0000F0FF
#define 		MASK_CIDR_15				0x0000FEFF
#define			MASK_CIDR_16				0x0000FFFF
#define			MASK_CIDR_24				0x00FFFFFF
#define			MASK_CIDR_32				0xFFFFFFFF

/* MAX_HOSTS value in CIDR Integer format for a network id */
#define 		MAXHOSTS_CIDR_4				0x10
#define			MAXHOSTS_CIDR_8				0x1
#define			MAXHOSTS_CIDR_10			0x4000
#define			MAXHOSTS_CIDR_12			0x1000
#define 		MAXHOSTS_CIDR_15			0x0200
#define			MAXHOSTS_CIDR_16			0x0100
#define			MAXHOSTS_CIDR_24			0x010000


/* RESTRICTED BLOCKS ADDRESS FROM RFCS */
#define			RB_224_0_0_0__4				0xE0
#define 		RB_240_0_0_0__4				0xF0
#define 		RB_0_0_0_0__8				0x00
#define 		RB_10_0_0_0__8 				0x0A
#define 		RB_127_0_0_0__8				0x7F
#define 		RB_100_64_0_0__10			0x4064
#define 		RB_172_16_0_0__12			0x10AC
#define 		RB_198_18_0_0__15			0x12C6
#define 		RB_169_254_0_0__16			0xFEA9
#define 		RB_192_168_0_0__16			0xA8C0
#define 		RB_192_0_0_0__24			0x0000C0
#define 		RB_192_0_2_0__24			0x0200C0
#define 		RB_192_88_99_0__24			0x6358C0
#define			RB_198_51_100_0__24			0x6433C6
#define			RB_203_0_113_0__24			0x7100CB

struct _uint32_bytes {
	unsigned char byte[4];
};

typedef struct _uint32_bytes uint32_bytes;

void print_ipv4_from_uint32 (unsigned int);

unsigned int reverse_bytes (unsigned int);

bool is_broadcast (unsigned int);
bool is_network (unsigned int);
bool is_in_rblock (unsigned int);
bool is_valid_ipv4_host (unsigned int);

unsigned int filter_rb_inc (unsigned int);
unsigned int filter_valid_ipv4_host (unsigned int);

#endif
