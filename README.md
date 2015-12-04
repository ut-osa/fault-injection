swifi
=====

This code is a rewrite and adaption of the kerenl software fault
injection framework originally from Chen et. al. as part of [1] and
modified by Swift et. al. for [2].  We have incorporated new faults
and a more general fault model inspired by a study on Linux faults [3]
and on filesystem patches [4].  In addition, some ideas and
implementation details were guided by a kernel Oops study [5].

This is targeted for x86-64 only due to assumptions made about the
compiler and within the disassembler and offset parsing.  This is not
an inherent limitation in the framework.  This is also only targeted
to be compiled into the Linux kernel and not as a kernel module.

Interface
---------

The user level interface provides a number of functions:

./swifi debug

    Rotate through the different verbosity and debug modes.

    * Mode 0 should printk quietly and use the random seed to
      indirectly re-seed itself.
	  
	* Mode 1 uses KERN_ALERT to printk.
	
	* Mode 2 uses KERN_ALERT to printk but passes the random seed in
      directly.  This allows some control over which address is
      initially choosen for the first fault.

    The code is initialized to Mode 0.

./swifi target type numfaults rand_seed

    These parameters are initialized to:
	
	    type = text
		numfaults = 1
		rand_seed = 1

- target:

    all:
	Choose an address from the kernel text and kernel module text.
	
	kernel:
	Chooses an address from the kernel text.

	range: addr:length
	Choose a kernel address between (0xffffffff00000000UL | addr) and
	up to length.
	
	kernel-module:
	Chooses an address from the designated kernel module.

- type:

    text:	Flip a random bit within <target>
	stack:	Flip a random bit on a random task stack
	init:	Nop away a stack variable initialization
	nop:	Nop out a random instruction
	dst/src:	Flip a bit in mod/rm, sib, disp, or imm fields
	branch:	Nop out a conditional jump or loop
	ptr:	Flip a bit in mod/rm
	free:	Replace calls to kernel alloc and free functions to try to get use-after-free or double-frees
	bcopy:	Add 128 bytes to %rcx before a rep mov
	invert:	Invert a conditional branch or loop
	mem_leak:	Nop out a call to a kernel free function
	interface:	Nop out a 'mov XX(rsp) reg' or 'mov XX(rbp) reg'
	direct:	A directed bit flip
	panic:	Call panic
	while1:	Go into a while(1) loop
	irq:	Nop out a push / popf or pushf / pop pair
	alloc:	Replace a call to a kernel alloc function with one that always returns NULL
	intrpt:	Nop a cli or sti instruction
	alloc_sz:	Replace a call to a kernel alloc function with one which undersizes the buffer
	blocking:	Replace a call to a kernel alloc function that always adds __GFP_WAIT
	obo:	Replace a conditional jump to be off-by-one (e.g., less than -> less than or equal)
	float:	Add 'movqu %rsp %xmm0' before a return
	var:	Change sub %rsp, add %rsp pairs to allocate an additional 1024 bytes
	atomic:	Nop out a call to spin_lock, mutex_lock, read_lock, or write_lock
	unlock:	Nop out a call to spin_unlock, mutex_unlock, read_unlock, or write_unlock

    kernel:	Choose random faults from the "kernel fault" distribution
	fs:	Choose random faults from the "filesystem fault" distribution

The additional fault distributions are based on distributions from a
Linux kernel fault study [3] and from a Linux kernel patch study [4].
The distribution is roughly drawn from these distributions.  A few
faults were not included due to limitations in the binary rewriting
and were instead replaced by a selection of random text faults.

Changes
-------

Beyond the code restructing, there are a number of changes to both how
faults are injected as well as what types of faults are supported.

- Fault types removed:

1. HEAP_FAULT
2. SYNC_FAULT
3. WP_FAULT
4. CPU_RESET_FAULT
5. COW_FAULT
6. DISK_TEST

In addition, the enum for STATS is ignored.

- New fault types:

1. INTRPT_FAULT -- Remove interrupt related handling
2. ALLOC_SZ_FAULT -- Change the requested allocation size of kmalloc and kzalloc
3. BLOCKING_FAULT -- Change the gfp_t flags of an allocation to always include __GFP_WAIT
4. OBO_FAULT -- Off by one error
5. FLOAT_FAULT -- Replace extra nops at the end of a function to  movqu %rsp %xmm0 
6. VAR_FAULT -- Allocate a large (1024 byte) variable on the stack
7. ATOMIC_FAULT -- Replace calls to spin_lock, mutex_lock, write_lock, and read_lock with nops
8. UNLOCK_FAULT -- Replace calls to spin_unlock, mutex_unlock, write_unlock, and read_unlock with nops

In addition, there are two fault models we try to incorporate into the
framework: A kernel fault model based on "Faults in Linux: Ten Years
Later" [1], and a filesystem fault model based on "A Study of Linux
File System Evolution" [2].  In addition, code examples from Yoshimura
et. al. [3] provided some additional inspiration for faults.

Bibliography
------------

[1] Peter M. Chen, Wee Teck Ng, Subhachandra Chandra, Christopher Aycock, and David Rajamani, Gurushankarand Lowell. The rio file cache: Surviving operating system crashes. In ASPLOS, pages 74–83, 1996.

[2] Michael M. Swift, Brian N. Bershad, and Henry M. Levy. Improving the reliability of commodity operating systems. In SOSP, pages 207–222, 2003.

[3] Nicolas Palix, Gae ̈l Thomas, Suman Saha, Christophe Calve`s, Julia Lawall, and Gilles Muller. Faults in linux: Ten years later. In ASPLOS, pages 305–318, 2011.

[4] Lanyue Lu, Andrea C Arpaci-Dusseau, Remzi H Arpaci-Dusseau, and Shan Lu. A study of linux file system evolution. In FAST, pages 31–44, 2013.

[5] Takeshi Yoshimura, Hiroshi Yamada, and Kenji Kono. Is linux kernel oops useful or not. In HotDep, 2012.


