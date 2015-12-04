/*
 * fault-model.c -- fault injection code for drivers
 *
 * Copyright (c) 2014 <anonymous submission>
 * Copyright (c) 2013 Takeshi Yoshimura
 * Copyright (C) 2003 Mike Swift
 * Copyright (c) 1999 Wee Teck Ng
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  No warranty
 * is attached; * we cannot take responsibility for errors or
 * fitness for use.
 *
 */

/*
 * Fault injector for testing the crash consistency of sego
 *
 * Adapted from the SWIFI tools used by Mike Swift to evaluate NOOKS
 * at the University of Washington and by Wee Teck Ng to evaluate the
 * RIO file cache at the University of Michigan
 *
 */

/*
 * This tool can inject faults into the guest kernel and/or specific
 * kernel modules.
 *
 * There are several classes of faults emulated:
 * - Corruption of text
 *    - corruption
 *    - simulated programming faults
 *         - skip initialization (immediate write to EBP-x)
 *         - remove instruction (replace with NOP)
 *	   - incorrect source/destination (corrupted)
 *         - remove jmp or rep instruction
 *         - change address computation for memory access (not stack)
 *	   - change termination condition for loop (change repeat to repeat
 *           -while equal, change condition to !condition
 - remove instructions loading registers from arguments (ebp+x)
 *
 * - corruption of stack
 * - corruption of heap
 * - copy overruns
 * - use after free
 */

#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/page.h>
#include <asm/sections.h>

#include "ddb.h"
#include "db_sym.h"
#include <linux/swifi.h>

#define CRASH_INTERVAL	8192
#define FI_MASK			0xfff
#define P50     0x3fffffff      /* 50% of max rand */
#define P94     0x7851eb84      /* 94% of max rand */
#define NOP		0x90
/* The original version is 0x1f */
#define RAND_BIT_MASK	0x3f

unsigned long randomSeed = 0;		/* random number */
unsigned long injectFault = 1;		/* inject fault ? */
unsigned long diskTest = 0;	        /* run disk test instead of rio */
unsigned long faultInjected = 0;        /* has fault been injected? */
unsigned long crashInterval = 0;        /* interval between injecting fault */
unsigned long crashCount = 0;	        /* number of times fault is injected */
unsigned long faultType;
unsigned long numFaults;
#define MAX_CRASH_ADDR 64
uint8_t *crashAddrs[MAX_CRASH_ADDR] = {NULL};	/* track current malloc */
struct kmem_cache *crashCache[MAX_CRASH_ADDR] = {NULL};	/* track associated cachep */
int nextAddr = 0;
int crashToggle = 1;
char *targetName = NULL;

static int debug = 0;

/* movq %rsp, %xmm0 */
#define FLOAT_FAULT_INSTR "\x66\x48\x0f\x6e\xc4"

int text_fault(uintptr_t start, size_t len, struct swifi_result *res);
int stack_fault(struct swifi_result *res);
int heap_fault(struct swifi_result *res);
int direct_fault(int fault_address, int fault_content, struct swifi_result *res);
int direct_fault1(int fault_address, int fault_content, struct swifi_result *res);
int while1(void);

int *testVA;

#if 1 /* def DEBUG */
#define PDEBUG(fmt, args...)						\
	do {								\
		if (debug) printk(KERN_ALERT "SWIFI: " fmt, ## args);	\
		else printk("SWIFI: " fmt, ## args);			\
	} while (0)
#else
#define PDEBUG(fmt, args...)
#endif

void swifi_toggle_verbose(void)
{
	debug = (debug + 1) % 3;
	printk(KERN_ALERT "SWIFI: set debug to %d\n", debug);
}

/* This expects an allocated page */
int swifi_set_target_name(char *target_name)
{
	targetName = target_name;
	return 0;
}
EXPORT_SYMBOL(swifi_set_target_name);

char *swifi_get_target_name(void)
{
	return targetName;
}
EXPORT_SYMBOL(swifi_get_target_name);

static int __module_add_length(void *len, struct module *mod)
{
	size_t *text_len = (size_t *)len;
	if (text_len && mod) {
		*text_len += mod->core_text_size;
		return 0;
	}
	return -ENOENT;
}

static int swifi_get_range(uintptr_t *text_start, size_t *text_len)
{
	struct module *mod;
	int rc = 0;
	uintptr_t tmp_start;
	uintptr_t tmp_len;

	/* Nothing set */
	if (!targetName || strcmp(targetName, "kernel") == 0)
		return 0;

	/* Range */
	if (strncmp(targetName, "range", 5) == 0) {
		tmp_start = *(uint64_t *)(targetName + 8);
		tmp_len = *(uint64_t *)(targetName + 16);
		if (tmp_start >= *text_start && tmp_len) {
			*text_start = tmp_start;
			*text_len = tmp_len;
			return 0;
		}
		return -ENOENT;
	}

	/* All */
	if (strcmp(targetName, "all") == 0) {
		mutex_lock(&module_mutex);
		rc = each_module(__module_add_length, text_len);
		mutex_unlock(&module_mutex);
		return rc;
	}

	/* Kernel module */
	mutex_lock(&module_mutex);
	mod = find_module(targetName);
	mutex_unlock(&module_mutex);
	if (mod) {
		*text_start = (uintptr_t)mod->module_core;
		*text_len = mod->core_text_size;
		return 0;
	}

	return -ENOENT;
}

int choose_fault(int model)
{
	int fault = -1;
	uint32_t rand = random() % 100; /* Out of 100 */
	switch (model) {
	case KERNEL_FAULT:
		if (rand < 15) {
			fault = UNLOCK_FAULT;
			PDEBUG("unlock fault\n");
		} else if (rand < 25) {
			fault = IRQ_FAULT;
			PDEBUG("irq fault\n");
		} else if (rand < 35) {
			fault = FLOAT_FAULT;
			PDEBUG("float fault\n");
		} else if (rand < 45) {
			fault = ALLOC_SZ_FAULT;
			PDEBUG("size fault\n");
		} else if (rand < 70) {
			fault = BLOCKING_FAULT;
			PDEBUG("blocking fault\n");
		} else if (rand < 75) {
			fault = VAR_FAULT;
			PDEBUG("var fault\n");
		} else if (rand < 80) {
			fault = BCOPY_FAULT;
			PDEBUG("bcopy fault\n");
		} else if (rand < 85) {
			fault = INTRPT_FAULT;
			PDEBUG("interrupt fault\n");
		} else if (rand < 95) {
			fault = FREE_FAULT;
			PDEBUG("use-after-free fault\n");
		} else if (rand < 100) {
			fault = TEXT_FAULT;
			PDEBUG("text fault\n");
		}
		break;
	case FS_FAULT:
		if (rand < 35) {
			fault = ATOMIC_FAULT;
			PDEBUG("atomic fault\n");
		} else if (rand < 50) {
			fault = BLOCKING_FAULT;
			PDEBUG("blocking fault\n");
		} else if (rand < 55) {
			fault = UNLOCK_FAULT;
			PDEBUG("unlock fault\n");
		} else if (rand < 80) {
			fault = MEM_LEAK_FAULT;
			PDEBUG("mem-leak fault\n");
		} else if (rand < 85) {
			fault = FREE_FAULT;
			PDEBUG("use-after-free fault\n");
		} else if (rand < 90) {
			fault = INIT_FAULT;
			PDEBUG("init fault\n");
		} else if (rand < 100) {
			fault = TEXT_FAULT;
			PDEBUG("text fault\n");
		}
		break;
	}
	return fault;
}

long swifi_do_faults(struct swifi_fault_params *p)
{
	/* Do we want to do this from a kernel thread? */
	long rc = -EINVAL;
	struct swifi_result *result = NULL;
	unsigned long rand_seed = p->seed;
	uintptr_t fault_address = 0;
	uintptr_t fault_data = 0;
	/* This is misses (addr >= VSYSCALL_START) && (addr < VSYSCALL_END) */
	uintptr_t text_start = (uintptr_t)_stext;
	size_t text_len = (size_t)(_etext - _stext);
	unsigned long cr0, new_cr0;
	int fault_model = 0, fault_count = 0;
	numFaults = p->faults;

	faultType = p->type;

	if (numFaults > SWIFI_MAX_FAULTS) {
		rc = -E2BIG;
		goto out;
	}

	rc = swifi_get_range(&text_start, &text_len);
	if (rc < 0) {
		goto out;
	}
	result = (struct swifi_result *)kmalloc(sizeof(*result) * (numFaults + 1),
						GFP_KERNEL);
	if (result == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(result, 0, sizeof(*result) * (numFaults + 1));

	/* Basically deprecated */
	if (faultType >= DISK_TEST) {
		faultType = faultType - DISK_TEST;
		diskTest = 1;
	}


	/* Set CR0 to turn off write protection */
	asm("movq %%cr0, %%rax\n\t" : "=a"(cr0));
	new_cr0 = cr0 & ~X86_CR0_WP;
	asm("movq %%rax, %%cr0\n" : : "a"(new_cr0));

	if (faultType == STATS) {
            /* Maybe this should collect some kind of stats */
#if 0
		extern long time_vmp, n_vmp;
		extern long time_pmp, n_pmp;

		PDEBUG("# vm_map_protect=%ld, total cycle=%ld\n", n_vmp, time_vmp);
		PDEBUG("# pmap_protect=%ld, total cycle=%ld\n", n_pmp, time_pmp);
		n_vmp=0; time_vmp=0;
		n_pmp=0; time_pmp=0;
#endif
	} else if (faultType == DIRECT_FAULT) {
		fault_address = numFaults;
		fault_data = rand_seed;
		PDEBUG("sys inject fault, type %ld, addr=%lx, flip bit%lx\n",
			faultType, fault_address, fault_data);
	} else if (faultType == DIRECT_FAULT1) {
		fault_address = numFaults;
		fault_data = rand_seed;
		PDEBUG("sys inject fault, type %ld, addr=%lx, zero bytes %lx\n",
			faultType, fault_address, fault_data);
	} else {
		PDEBUG("sys inject fault, type %ld, seed=%ld, fault=%ld\n",
			faultType, rand_seed, numFaults);
	}

	if (faultType == KERNEL_FAULT || faultType == FS_FAULT) {
		/* Follow a particular fault model */
		fault_model = faultType;
		fault_count = numFaults;
		numFaults = 1;
	}

	faultInjected = 1;
	srandom(rand_seed);
	if (debug <= 1) {
		uint32_t rerand = random() & 0x7;
		for (; rerand > 0; rerand --) {
			(void)random();
		}
	}

	/* set warm reboot, leave RAM unchanged
	 * 0 : don't inject fault
	 * 1 : run POST, wipe out memory
	 * 2 : don't test memory
	 * 3 : don't change memory (doesn't work)
	 * 4 : don't sync registry
	 */

repeat:
	if (fault_model) {
		faultType = choose_fault(fault_model);
	}

	/* default number of faults is: you better know what you're doing  */

	switch (faultType) {
	case TEXT_FAULT:
		rc = text_fault(text_start, text_len, result);
		break;
	case STACK_FAULT:
		rc = stack_fault(result);
		break;
	case HEAP_FAULT:
		rc = heap_fault(result);
		break;
	case INIT_FAULT:
	case NOP_FAULT:
	case DST_FAULT:
	case SRC_FAULT:
	case BRANCH_FAULT:
	case PTR_FAULT:
	case BCOPY_FAULT:
	case INVERT_FAULT:
	case OBO_FAULT:
	case INTERFACE_FAULT:
	case IRQ_FAULT:
	case INTRPT_FAULT:
	case FLOAT_FAULT:
	case VAR_FAULT:
	/* 5l: mem */
	case FREE_FAULT:
	case MEM_LEAK_FAULT:
	case ALLOC_FAULT:
	case ALLOC_SZ_FAULT:
	case BLOCKING_FAULT:
	/* 5m: lck */
	case ATOMIC_FAULT:
	case UNLOCK_FAULT:
		rc = text_fault(text_start, text_len, result);
		break;
	case SYNC_FAULT:
		crashInterval = CRASH_INTERVAL; 	/* interval between crash */
		break;
	case PANIC_FAULT:
		panic("testing panic");
		rc = 0;
		break;
	/* case WP_FAULT: */
	/* 	page_reg_fault(random()); */
	/* 	break; */
	case DIRECT_FAULT:
		direct_fault(fault_address, fault_data, result);
		break;
	case DIRECT_FAULT1:
		rc = direct_fault1(fault_address, fault_data, result);
		break;
	/* case PAGE_REG_DUMP: */
	/* 	rio_dump(); */
	/* 	break; */
	case WHILE1_FAULT:
		rc = while1();
		break;
	/* case CPU_RESET_FAULT: */
	/* 	cpu_reset(); */
	/* 	break; */
	/* case COW_FAULT: { */
		/* test writing to kernel text. freebsd currently do a COW on a
		 * write to kernel text.
		 */
		/* This no longer works: (tested on version Linux
		 * 2.6.36) Writing to kernel text causes a page fault
		 * and segfault.
		 */
	/* 	unsigned long *addr1, *addr2; */

	/* 	addr1 = (unsigned long *) 0xf0212000; */
	/* 	addr2 = (unsigned long *) 0xf0212010; */
	/* 	PDEBUG("%p=%lx, %p=%lx\n", addr1, *addr1, addr2, *addr2); */
	/* 	__asm__ ("movl $0xf0212000, %eax\n\t" */
	/* 		"movl $6, 0(%eax)\n\t" */
	/* 		"movl $6, 4(%eax)\n\t"); */
	/* 	addr1 = (unsigned long *) 0xf0212000; */
	/* 	addr2 = (unsigned long *) 0xf0212010; */
	/* 	PDEBUG("after injecting fault\n"); */
	/* 	PDEBUG("%p=%lx, %p=%lx\n", addr1, *addr1, addr2, *addr2); */
	/* 	rc = 0; */
	/* 	break; */
	/* } */

	case DEBUGGER_FAULT:
		PDEBUG("Debugger fault\n");
#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif
		__asm__ ("mov"Q" %cr4, %"R"cx\n\t"
			"mov"Q" $42, %"R"cx; .byte 0x0f, 0x32\n\t"
			"mov"Q" $377, %"R"cx; .byte 0x0f, 0x32\n\t");
#undef R
#undef Q
		rc = 0;
		break;
	default:
		PDEBUG("unknown fault type %ld\n", faultType);
		break;
	}

	if (fault_model && --fault_count > 0) {
		goto repeat;
	}

	/* Fix CR0 */
	asm("movq %%rax, %%cr0\n" : : "a"(cr0));

	if (copy_to_user(p->record, result, p->faults * sizeof(struct swifi_result))) {
		rc = -EFAULT;
	}

out:
	if (result != NULL) {
		kfree(result);
	}
	return rc;
}
EXPORT_SYMBOL(swifi_do_faults);

int while1(void)
{
	int i = 0;

	PDEBUG("entering into while 1 loop\n");
	while(1) {
		udelay(20000);
		PDEBUG("delay %4d secs, cpl=0x%x, ipend=0x%x\n", i+=5, 20, 30);
		if (i > (100 * 2500))
			break;
	}
	return 0;
}

int direct_fault(int fault_address, int fault_content, struct swifi_result *res)
{
	unsigned long *addr;
	int flip_bit = 0;

	addr = (unsigned long *) (PAGE_OFFSET + fault_address);

	PDEBUG("%p:0x%lx => ", addr, *addr);

	flip_bit = 1 << fault_content;

	res[0].address = (unsigned long) addr;
	res[0].old = *addr;
	res[0].new = (*addr) ^ flip_bit;
	if (injectFault) {
		*addr = (*addr) ^ flip_bit;
	}

	PDEBUG("%lx\n", *addr);
	return(0);
}

int direct_fault1(int fault_address, int fault_content, struct swifi_result *res)
{
	unsigned long *addr, data;

	addr = (unsigned long *) (PAGE_OFFSET + fault_address);

	PDEBUG("%p:%lx => ", addr, *addr);

	data = *addr;
	if(fault_content==1) {
		data = data & 0xffffff00;
		data = data | 0x00000090;
	} else if(fault_content==2) {
		data = data & 0xffff0000;
		data = data | 0x00009090;
	} else if(fault_content==3) {
		data = data & 0xff000000;
		data = data | 0x00909090;
	} else if(fault_content==4) {
		data = 0x90909090;
	}
	res[0].address = (unsigned long) addr;
	res[0].old = *addr;
	res[0].new = data;
	if (injectFault) {
		*addr = data;
	}

	PDEBUG("%lx\n", *addr);
	return(0);
}

#include <linux/sched.h>
#define MAX_NUM_TASKS 20
struct task_struct * find_task(void)
{
	struct task_struct * task = NULL, *result = NULL ;
	int i,j;
	i = 1 + (random() % MAX_NUM_TASKS);
	j = i;

	do {
		read_lock(&tasklist_lock);
		for_each_process(task) {
			if (--i == 0) {
				result = task;
				break;
			}
		}
		read_unlock(&tasklist_lock);
	} while ((i > 0) && (i != j));

	return(result);
}

int stack_fault(struct swifi_result *res)
{
	unsigned long *addr, size, taddr;
	int flip_bit = 0;
	int count = 0;
	struct task_struct *task = NULL;

	while (count < numFaults) {
		task = find_task();
		if (task == NULL) {
			return -1;
		}

		/* Need to figure out the top of the stack */
		size = (unsigned long)(task->stack + THREAD_SIZE - task->thread.sp);

		PDEBUG("stack range = %lx-%lx\n", task->thread.sp, task->thread.sp + size);

		addr = (unsigned long *) ((long) task->thread.sp +
					(random() & ~0x3) % size);
		taddr = (unsigned long) addr;
		flip_bit = random() & RAND_BIT_MASK;
		PDEBUG("%lx:%lx flip bit %d => ", taddr, *addr, flip_bit);
		flip_bit = 1 << flip_bit;
		res[count].address = taddr;
		res[count].old = *addr;
		res[count].new = (*addr) ^ flip_bit;
		if (injectFault) {
			*addr = (*addr) ^ flip_bit;
		}

		PDEBUG("%lx\n", *addr);
		count++;
	}
	return(0);
}

//
// Instead of dealing with heaps directly, we look at the area cache of pages
// and vm pages and find an address there.
//
int heap_fault(struct swifi_result *res)
{
#ifdef notdef
	unsigned long *addr, taddr;
	int flip_bit=0;
	int count=0;
	unsigned long flags;
	struct list_head *next;

	do {
	addr = (unsigned long *) (map->address + (random()&~0xf)%map->size);

	taddr=(unsigned long) addr;
	flip_bit = random() & RAND_BIT_MASK;
	PDEBUG("heap range=%lx-%lx ", map->address, map->address + map->size);
	PDEBUG("%lx:%lx flip bit %d => ", taddr, *addr, flip_bit);
	flip_bit = 1 << flip_bit;
	res[count].address = taddr;
	res[count].old = *addr;
	res[count].new = (*addr) ^ flip_bit;
	if (injectFault) {
		*addr = *addr ^ flip_bit;
	}
	PDEBUG("%lx\n", *addr);
	count++;
	} while (count < numFaults);
#endif
	return -1;
}

/**
 * Use after free:
 *
 * ALlocate and free as normal except also track valid allocated
 * targets so we can later free early (or double free).
 */
static inline void *swifi_alloc(void *addr, void *cache)
{
	crashAddrs[nextAddr] = addr;
	crashCache[nextAddr] = cache;
	nextAddr = (nextAddr + 1) % MAX_CRASH_ADDR;
	return addr;
}

static inline void swifi_free(void)
{
	int choice = random() % MAX_CRASH_ADDR;
	if ((random() & 0x03) == 0) {
		if (crashCache[choice] != NULL) {
			kmem_cache_free(crashCache[choice], crashAddrs[choice]);
		} else if (crashAddrs[choice] != NULL) {
			kfree(crashAddrs[choice]);
		}
		crashAddrs[choice] = NULL;
		crashCache[choice] = NULL;
	}
}

void *swifi_uaf_kmalloc(size_t size, gfp_t gfp)
{
	return swifi_alloc(kmalloc(size, gfp), NULL);
}

void *swifi_uaf_kzalloc(size_t size, gfp_t gfp)
{
	return swifi_alloc(kzalloc(size, gfp), NULL);
}

void swifi_uaf_kfree(const void *addr)
{
	kfree(addr);
	swifi_free();
}

void *swifi_uaf_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t gfp)
{
	return swifi_alloc(kmem_cache_alloc(cachep, gfp), cachep);
}

void swifi_uaf_kmem_cache_free(struct kmem_cache *cachep, void *addr)
{
	kmem_cache_free(cachep, addr);
	swifi_free();
}

/**
 * Faulty kmalloc
 *
 * Right now, always return NULL.  Maybe we should randomize this in
 * the future.
 */
void *swifi_fault_kmalloc(size_t size, gfp_t flags)
{
	/* Always return NULL? */
	return NULL;
}

void *swifi_fault_kzalloc(size_t size, gfp_t flags)
{
	/* Always return NULL? */
	return NULL;
}

void *swifi_fault_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	/* Always return NULL? */
	return NULL;
}

/**
 * Faulty size kmalloc
 *
 * Randomly resize the size parameter.  Minimally set kmalloc to 8.
 */
void *swifi_sz_kmalloc(size_t size, gfp_t flags)
{
	int shift_bit = random() & 0x3;
	size = size >> shift_bit;
	if (!size)
		size = 8;
	return kmalloc(size, flags);
}

void *swifi_sz_kzalloc(size_t size, gfp_t flags)
{
	int shift_bit = random() & 0x3;
	size = size >> shift_bit;
	if (!size)
		size = 8;
	return kzalloc(size, flags);
}

/**
 * Faultly blocking kmalloc
 *
 * Always add __GFP_WAIT to the flags.
 */
void *swifi_block_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags | __GFP_WAIT);
}

void *swifi_block_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags | __GFP_WAIT);
}

void *swifi_block_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return kmem_cache_alloc(cachep, flags | __GFP_WAIT);
}

static inline uint8_t *skip_prefix(uint8_t *instr)
{
	int prefix = 0;
	do {
		switch (*instr) {
		case 0x66: case 0x67: case 0x26: case 0x36:
		case 0x2e: case 0x3e: case 0x64: case 0x65:
		case 0xf0: case 0xf2: case 0xf3:
			/* x86 64 prefixes */
		case 0x40: case 0x41: case 0x42: case 0x43:
		case 0x44: case 0x45: case 0x46: case 0x47:
		case 0x48: case 0x49: case 0x4a: case 0x4b:
		case 0x4c: case 0x4d: case 0x4e: case 0x4f:
			prefix = 1;
			break;
		default:
			prefix = 0;
			break;
		}
		if (prefix) {
			instr++;
		}
	} while (prefix);
	return instr;
}

static int __module_get_addr(void *off, struct module *mod)
{
	unsigned long *addr_off = off;
	int rc = 0;
	if (addr_off && mod) {
		if (*addr_off < mod->core_text_size) {
			rc = (int)(*addr_off);
			*addr_off = (unsigned long)mod->module_core;
		} else {
			*addr_off -= mod->core_text_size;
		}
	} else {
		*addr_off = 0;
		rc = -1;
	}
	return rc;
}

static uintptr_t get_faulty_alloc(int type)
{
	uintptr_t faulty_alloc = 0;
	if (faultType == ALLOC_FAULT) {
		switch (type) {
		case KMALLOC:
			PDEBUG("Found kmalloc, replacing with swifi_fault_kmalloc");
			faulty_alloc = (uintptr_t)&swifi_fault_kmalloc;
			break;
		case KZALLOC:
			PDEBUG("Found kzalloc, replacing with swifi_fault_kzalloc");
			faulty_alloc = (uintptr_t)&swifi_fault_kzalloc;
			break;
		case KMEM_CACHE_ALLOC:
			PDEBUG("Found kmem_cache_alloc, "
				"replacing with swifi_fault_kmem_cache_alloc");
			faulty_alloc = (uintptr_t)&swifi_fault_kmem_cache_alloc;
			break;
		default:
			PDEBUG("Returned a %d call\n", type);
		}
	} else if (faultType == ALLOC_SZ_FAULT) {
		switch (type) {
		case KMALLOC:
			PDEBUG("Found kmalloc, replacing with swifi_sz_kmalloc");
			faulty_alloc = (uintptr_t)&swifi_sz_kmalloc;
			break;
		case KZALLOC:
			PDEBUG("Found kzalloc, replacing with swifi_sz_kzalloc");
			faulty_alloc = (uintptr_t)&swifi_sz_kzalloc;
			break;
		default:
			PDEBUG("Returned a %d call\n", type);
		}
	} else if (faultType == BLOCKING_FAULT) {
		switch (type) {
		case KMALLOC:
			PDEBUG("Found kmalloc, replacing with swifi_block_kmalloc");
			faulty_alloc = (uintptr_t)&swifi_block_kmalloc;
			break;
		case KZALLOC:
			PDEBUG("Found kzalloc, replacing with swifi_block_kzalloc");
			faulty_alloc = (uintptr_t)&swifi_block_kzalloc;
			break;
		case KMEM_CACHE_ALLOC:
			PDEBUG("Found kmem_cache_alloc, replacing with swifi_block_kmem_cache_alloc");
			faulty_alloc = (uintptr_t)&swifi_block_kmem_cache_alloc;
			break;
		default:
			PDEBUG("Returned a %d call\n", type);
		}
	}
	return faulty_alloc;
}

int text_fault(uintptr_t btext, size_t text_size, struct swifi_result *res)
{
	unsigned long *addr = NULL, aoff, offset, page, taddr;
	unsigned long etext = btext + text_size;
	int count, flip_bit = 0, len = 0, rc;
	unsigned char *c;

	/* inject faults into text space */
	for (count = 0; count < numFaults; count++) {
		int j;

		aoff = (random() % text_size) & ~0xf;
		if (targetName && strcmp(targetName, "all") == 0) {
			/* translate this */
			if (aoff < (size_t)(_etext - _stext)) {
				addr = (unsigned long *)(btext + aoff);
				text_size = (size_t)(_etext - _stext);
				etext = btext + text_size;
			} else {
				struct module *mod;
				aoff -= (size_t)(_etext - _stext);
				mutex_lock(&module_mutex);
				rc = each_module(__module_get_addr, &aoff);
				mod = __module_text_address(aoff);
				mutex_unlock(&module_mutex);
				if (rc <= 0 || aoff == 0 || mod == NULL) {
					PDEBUG("did not find a matching module, skipping");
					continue;
				}
				btext = (unsigned long)mod->module_core;
				text_size = mod->core_text_size;
				etext = btext + text_size;
				addr = (unsigned long *)(mod->module_core + rc);
			}
		} else {
			addr = (unsigned long *)(btext + aoff);
		}
		/* now the tricky part */

		taddr = (unsigned long)addr;
		if (faultType == INIT_FAULT ||
		    faultType == NOP_FAULT ||
		    faultType == DST_FAULT ||
		    faultType == SRC_FAULT ||
		    faultType == BRANCH_FAULT ||
		    faultType == PTR_FAULT ||
		    faultType == BCOPY_FAULT ||
		    faultType == INVERT_FAULT ||
		    faultType == INTERFACE_FAULT ||
		    faultType == IRQ_FAULT ||
		    faultType == INTRPT_FAULT ||
		    faultType == OBO_FAULT ||
		    faultType == FLOAT_FAULT ||
		    faultType == VAR_FAULT ||
		    faultType == ALLOC_FAULT ||
		    faultType == ALLOC_SZ_FAULT ||
		    faultType == FREE_FAULT ||
		    faultType == MEM_LEAK_FAULT ||
		    faultType == ATOMIC_FAULT ||
		    faultType == UNLOCK_FAULT) {
			addr = (unsigned long *)find_faulty_instr_range(btext, etext, taddr,
									faultType, &len, debug);
			/* do it over again if we can't find the right instruction */
			if (!addr || !len) {
				continue;
			}
		}

		printk("instr addr=%p, ", addr);
		if (len) {
			c = (unsigned char *)addr;
			if (faultType == FREE_FAULT ||
			    faultType == ALLOC_FAULT ||
			    faultType == ALLOC_SZ_FAULT ||
			    faultType == BLOCKING_FAULT) {
				for (j = 0; j < (len >> 4); j++) {
					printk(KERN_CONT " %02x", c[j]);
				}
			} else {
				for (j = 0; j < len; j++) {
					printk(KERN_CONT " %02x", c[j]);
				}
			}
			printk(" =>");

		} else {
			printk("%lx =>", *addr);
		}

		offset = (unsigned long)addr & PAGE_MASK;
		page = (unsigned long)addr & ~PAGE_MASK;

		/* it doesn't matter what we used here to unprotect page,
		 * as this routine will not be in production code.
		 */
		/* unprotect by clearing the WR_PROT bit in cr0
		 */

		res[count].address = taddr;
		res[count].old = *addr;
		res[count].new = *addr;

		if (faultType == TEXT_FAULT) {
			flip_bit = random() & RAND_BIT_MASK;
			printk("flip bit %d => ", flip_bit);
			flip_bit = 1 << flip_bit;
			res[count].new = (*addr) ^ flip_bit;
			if (injectFault) {
				*addr = ((*addr) ^ flip_bit);
			}
		} else if (faultType == NOP_FAULT ||
			faultType == INIT_FAULT ||
			faultType == BRANCH_FAULT ||
			faultType == INTERFACE_FAULT ||
			faultType == IRQ_FAULT ||
			faultType == INTRPT_FAULT ||
			/* NOP out the call to kfree */
			faultType == MEM_LEAK_FAULT ||
			faultType == ATOMIC_FAULT ||
			faultType == UNLOCK_FAULT) {
			c = (unsigned char *) addr;

			for (j = 0; j < len; j++) {
				/* replace these bytes with NOP (*c=NOP) */
				if (j < sizeof(unsigned long)) {
					((unsigned char *) &res[count].new)[j] = NOP;
				}
				if (injectFault) {
					*c = NOP;
				}
				c++;
			}
		} else if (faultType == DST_FAULT || faultType == SRC_FAULT) {
			/* skip thru the prefix and opcode, and flip bits in following bytes */
			c = skip_prefix((uint8_t *)addr);
			if (*c >= 0xd8 && *c <= 0xdf) {
				/* don't mess with fp instruction, yet.
				 * but there shouldn't be any fp instr in kernel.
				 */
				PDEBUG("floating point instruction, bailing out\n");
				continue;
			} else if (*c == 0x0f) {
				c++;
			}
			if (*c == 0x0f) {
				c++;
			}
			c++;
			len = len - ((long)c - (long)addr);
			flip_bit = random() % (len*8);
			printk("flip bit %d (len=%d) => ", flip_bit, len);
			for (j = 0; j < len; j++) {
				/* go to the right byte */
				if (flip_bit < 8) {
					flip_bit = 1 << flip_bit;
					if (j < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[j] = (*c) ^ flip_bit;
					}
					if (injectFault) {
						*c = *c ^ flip_bit;
					}
					j = len;
				}
				c++;
				flip_bit = flip_bit - 8;
			}
		} else if (faultType == PTR_FAULT) {
			/* 5f) ptr: if instruction has regmodrm byte (i_has_modrm),
			 *     flip 1 bit in lower byte (0x0f) or any bit in following
			 *     bytes (sib, imm or disp).
			 */
			c = skip_prefix((uint8_t *)addr);
			if (*c >= 0xd8 && *c <= 0xdf) {
				/* don't mess with fp instruction, yet */
				PDEBUG("floating point instruction, bailing out\n");
				continue;
			} else if (*c == 0x0f) {
				c++;
			}
			if (*c == 0x0f) {
				c++;
			}
			c++;
			len = len - ((long)c - (long)addr);
			flip_bit = random() % (len * 8 - 4);
			printk("flip bit %d (len=%d) => ", flip_bit, len);

			/* mod/rm byte is special */
			if (flip_bit < 4) {
				flip_bit = 1 << flip_bit;
				rc = c - (unsigned char *) addr;
				if (rc < sizeof(unsigned long)) {
					((unsigned char *) &res[count].new)[rc] = (*c) ^ flip_bit;
				}
				if (injectFault) {
					*c = *c ^ flip_bit;
				}
			}
			c++;
			flip_bit = flip_bit - 4;

			for (j = 1; j < len; j++) {
				/* go to the right byte */
				if (flip_bit < 8) {
					flip_bit = 1 << flip_bit;
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = (*c) ^ flip_bit;
					}
					if (injectFault) {
						*c = *c ^ flip_bit;
					}
					j = len;
				}
				c++;
				flip_bit = flip_bit - 8;
			}
		} else if (faultType == BCOPY_FAULT) {
			/* This should be of mov imm ecx */
			c = skip_prefix((uint8_t *)addr);
			if (*c == 0xb9) {
				if (len > 2) {
					c[2] += 1;
				} else {
					c[1] += 1;
				}
			} else if (*c == 0xc7 && c[1] == 0xc1) {
				if (len > 3) {
					c[3] += 1;
				} else {
					c[2] += 1;
				}
			} else {
				printk(KERN_ERR "There's different instruction! %02x %02x %02x\n",
					c[0], c[1], c[2]);
			}
		} else if (faultType == INVERT_FAULT) {
			c = skip_prefix((unsigned char *)addr);
			/* replace rep with repe, and vice versa */
			for (j = c - (unsigned char *)addr - 1; j >= 0 ; j--) {
				if (((uint8_t *)addr)[j] == 0xf3) {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = 0xf2;
					}
					if (injectFault) {
						*c = 0xf2;
					}
					break;
				} else if (((uint8_t *)addr)[j] == 0xf2) {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = 0xf3;
					}
					if (injectFault) {
						*c = 0xf3;
					}
					break;
				}
			}
			if (((*c) & 0xf0) == 0x70) {
				/* if we've jxx imm8 instruction,
				 * incl even byte instruction, eg jo (70) to jno (71)
				 * decl odd byte instruction,  eg jnle (7f) to jle (7e)
				 */
				if (*c % 2 == 0) {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = (*c) + 1;
					}
					if (injectFault) {
						*c = *c + 1;
					}
				}  else {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = (*c) - 1;
					}

					if (injectFault) {
						*c = *c - 1;
					}
				}
			} else if (*(c++) == 0x0f && ((*c) & 0xf0) == 0x80 ) {
				/* Apparently the above is legal
				 * c[0] == 0x0f && c[1] & 0xf0 == 0x80
				 */
				/* if we've jxx imm16/32 instruction,
				 * incl even byte instruction, eg jo (80) to jno (81)
				 * decl odd byte instruction,  eg jnle (8f) to jle (8e)
				 */
				if (*c % 2 == 0) {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = (*c) + 1;
					}
					if (injectFault) {
						*c = *c + 1;
					}
				} else {
					rc = (c - (unsigned char *) addr);
					if (rc < sizeof(unsigned long)) {
						((unsigned char *) &res[count].new)[rc] = (*c) -1;
					}
					if (injectFault) {
						*c = *c - 1;
					}
				}
			}
		} else if (faultType == OBO_FAULT) {
			c = skip_prefix((uint8_t *)addr);
			if (*c == 0x0f) {
				c ++;
				if ((*c & 0xf0) != 0x80) {
					continue;
				}
			} else if ((*c & 0xf0) != 0x70) {
				continue;
			}
			if (injectFault) {
				if ((*c & 0xc) == 0xc) {
					/* 0x7c <-> 0x7e, 0x0f8c <-> 0x0f8e
					 * 0x7d <-> 0x7f, 0x0f8d <-> 0x0f8f
					 * Check b11xx == b11xx */
					*c = *c ^ 2;
				} else if ((*c & 0xa) == 0x2) {
					/* 0x72 <-> 0x76, 0x0f82 <-> 0x0f86
					 * 0x73 <-> 0x77, 0x0f83 <-> 0x0f87
					 * Check b1x1x == b0x1x */
					*c = *c ^ 4;
				}
			}
		} else if (faultType == FLOAT_FAULT) {
			c = (uint8_t *)addr;
			if (*c == 0xc3) {
				/* movq %rsp, %xmm0 */
				memcpy(c, FLOAT_FAULT_INSTR, sizeof(FLOAT_FAULT_INSTR) - 1);
				c += sizeof(FLOAT_FAULT_INSTR) - 1;
				/* Fill remainder with nop */
				memset(c, 0x90, len - 6);
				c += (len - 6);
				/* Restore the ret */
				*c++ = 0xc3;
			}
		} else if (faultType == VAR_FAULT) {
			c = (uint8_t *)addr;
			if (*c == 0x48) c++;
			if ((c[0] == 0x81 || c[0] == 0x83) && c[1] == 0xec) {
				if (c[0] == 0x83) c[2] |= 0xf0;
				else c[3] += 0x04;
			}
		} else if (faultType == ALLOC_FAULT ||
			   faultType == BLOCKING_FAULT ||
			   faultType == ALLOC_SZ_FAULT) {
			/* Replace normal k*alloc with a faulty one.. */
			uintptr_t faulty_alloc = 0;
			int type = len & 0xf;
			c = (unsigned char *)addr;
			len = len >> 4;
			if (*c == 0xe8 && len == 5) {
				faulty_alloc = get_faulty_alloc(type) - (uintptr_t)(c++ + len);
				*(int *)(c) = (int)faulty_alloc;
			}
		} else if (faultType == FREE_FAULT) {
			/* Somehow turn this into a use after free. */
			uintptr_t faulty_call = 0;
			int type = len & 0xf;
			c = (unsigned char *)addr;
			len = len >> 4;
			if (*c == 0xe8 && len == 5) {
				switch (type) {
				case KMALLOC:
					printk("Found kmalloc, replacing with swifi_kmalloc");
					faulty_call = (uintptr_t)&swifi_uaf_kmalloc;
					break;
				case KZALLOC:
					printk("Found kzalloc, replacing with swifi_kzalloc");
					faulty_call = (uintptr_t)&swifi_uaf_kzalloc;
					break;
				case KFREE:
					printk("Found kfree, replacing with swifi_kfree");
					faulty_call = (uintptr_t)&swifi_uaf_kfree;
					break;
				case KMEM_CACHE_ALLOC:
					printk("Found kmem_cache_alloc, replacing with swifi_kmem_cache_alloc");
					faulty_call = (uintptr_t)&swifi_uaf_kmem_cache_alloc;
					break;
				case KMEM_CACHE_FREE:
					printk("Found kmem_cache_free, replacing with swifi_kmem_cache_free");
					faulty_call = (uintptr_t)&swifi_uaf_kmem_cache_free;
					break;
				default:
					printk("Returned a %d call\n", type);
				}
				faulty_call -= (uintptr_t)(c++ + len);
				*(int *)(c) = (int)faulty_call;
			}
		}
		if (len) {
			c = (unsigned char *)addr;
			for (j = 0; j < len; j++) {
				printk(KERN_CONT " %02x", c[j]);
			}
			printk(KERN_CONT "\n");
		} else {
			printk(" %lx\n", *addr);
		}
	}
	return 0;
}
