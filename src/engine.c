#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "ipv4.h"
#include "bool.h"
	
int
main (void)
{
	unsigned int addr = 0, newaddr;
	unsigned int random;
	unsigned long long laddr;
	unsigned long count = 0;
	float progress = 0;
	bool reset_pool_addr = false;
	clock_t start, end;
	time_t now;
	struct tm * timeinfo;
	double time_taken;

	srand (time(NULL));

	now = time(0);
	timeinfo = localtime(&now);

	printf("Starting Scout 0.1 at %s", asctime (timeinfo));

	start = clock();
	for ( ; ; ) {

		newaddr = filter_valid_ipv4_host (addr);
		if (newaddr == 0x1000001){ // first address given in the IPv4 pool
			if (reset_pool_addr) 
				break;
			else
				reset_pool_addr = true;
		}
		addr = newaddr;

		progress = (float)reverse_bytes(addr) / (float)(0xffffffff);
		progress *= 100;
		printf("(%3.2f\%) -  %x Target host is ", progress, addr);
		print_ipv4_from_uint32 (addr);

		count++;

		random = (unsigned int)((rand() % 0xfffffff) + 1);
		/* verify if overflow occurs - checks carry flag */
		printf("addr: %x\n", reverse_bytes(addr));
		printf("random: %x\n", random);
		laddr = (unsigned long long)random + (unsigned long long)reverse_bytes(addr);
		printf("laddr: %x\n", laddr);
		if (laddr >= 0xffffffff)
			break;
		
		addr = reverse_bytes (random + reverse_bytes(addr));
	}

	end = clock();
	time_taken = ((double)(end - start))/CLOCKS_PER_SEC;

	printf("Scout finished: %d IP(s) scanned in %f seconds.\n", count, time_taken);

	return 0;
}
