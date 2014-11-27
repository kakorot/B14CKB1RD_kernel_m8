#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/memblock.h>

#include <asm/setup.h>
#include <asm/bios_ebda.h>

#define BIOS_LOWMEM_KILOBYTES 0x413
#define LOWMEM_CAP		0x9f000U	/* Absolute maximum */
#define INSANE_CUTOFF		0x20000U	/* Less than this = insane */


void __init reserve_ebda_region(void)
{
	unsigned int lowmem, ebda_addr;

	/*
	 * To determine the position of the EBDA and the
	 * end of conventional memory, we need to look at
	 * the BIOS data area. In a paravirtual environment
	 * that area is absent. We'll just have to assume
	 * that the paravirt case can handle memory setup
	 * correctly, without our help.
	 */
	if (paravirt_enabled())
		return;

	
	lowmem = *(unsigned short *)__va(BIOS_LOWMEM_KILOBYTES);
	lowmem <<= 10;

	
	ebda_addr = get_bios_ebda();
	
	/*
	 * Note: some old Dells seem to need 4k EBDA without
	 * reporting so, so just consider the memory above 0x9f000
	 * to be off limits (bugzilla 2990).
	 */

	/* If the EBDA address is below 128K, assume it is bogus */
	if (ebda_addr < INSANE_CUTOFF)
		ebda_addr = LOWMEM_CAP;

	/* If lowmem is less than 128K, assume it is bogus */
	if (lowmem < INSANE_CUTOFF)
		lowmem = LOWMEM_CAP;

	/* Use the lower of the lowmem and EBDA markers as the cutoff */
	lowmem = min(lowmem, ebda_addr);
	lowmem = min(lowmem, LOWMEM_CAP); /* Absolute cap */
 
 	/* reserve all memory between lowmem and the 1MB mark */
	memblock_reserve(lowmem, 0x100000 - lowmem);
}
