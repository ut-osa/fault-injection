#ifndef _SWIFI_USER_H
#define _SWIFI_USER_H

#define TEXT_FAULT	0
#define STACK_FAULT	1
#define HEAP_FAULT	2	/* Removed */
#define INIT_FAULT	3
#define NOP_FAULT	4
#define DST_FAULT	5
#define SRC_FAULT	6
#define BRANCH_FAULT	7	/* nop branches or loops */
#define PTR_FAULT	8
#define FREE_FAULT	9
#define BCOPY_FAULT	10
#define SYNC_FAULT	11	/* Removed */
#define INVERT_FAULT	12	/* invert branches or loops */
#define MEM_LEAK_FAULT	13
#define INTERFACE_FAULT	14
#define DIRECT_FAULT	15
#define DIRECT_FAULT1	16
#define STATS		17	/* Removed */
#define WP_FAULT	19	/* Removed */
#define PANIC_FAULT	20
#define WHILE1_FAULT	21
#define DEBUGGER_FAULT	22
#define CPU_RESET_FAULT	23	/* Removed */
#define PAGE_REG_DUMP	24	/* Removed */
#define COW_FAULT	25	/* Removed */
#define IRQ_FAULT	26
#define ALLOC_FAULT	27
#define INTRPT_FAULT	28
#define ALLOC_SZ_FAULT	29
#define BLOCKING_FAULT	30
#define OBO_FAULT	31
#define FLOAT_FAULT	32
#define VAR_FAULT	33
#define ATOMIC_FAULT	34
#define UNLOCK_FAULT	35
#define KERNEL_FAULT	50
#define FS_FAULT	51
#define DISK_TEST	100	/* Removed */

#define SWIFI_MAX_FAULTS 1000

struct swifi_result {
	unsigned long address;
	unsigned long old;
	unsigned long new;
};

struct swifi_fault_params {
	void *record;
	unsigned long type;
	unsigned long faults;
	unsigned long seed;
};

#define SWIFI_MINOR		239

#define SWIFI_SET_TARGET	_IOR(SWIFI_MINOR, 0x01, char *)
#define SWIFI_DO_FAULTS		_IOR(SWIFI_MINOR, 0x02, struct swifi_fault_params)
#define SWIFI_VERBOSE		_IO(SWIFI_MINOR, 0x03)

#endif // _SWIFI_USER_H
