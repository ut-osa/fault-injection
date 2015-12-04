/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 *	$Id: db_sym.c,v 1.2 2003/01/16 01:06:09 mikesw Exp $
 */

/*
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */
/*
 * Modified: <anonymous submission>
 * Date:     03/14
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include "ddb.h"
#include "db_sym.h"
#include "extern.h"
#include <linux/swifi.h>

unsigned int	db_maxoff = 0x10000;
#if 1 /* def DEBUG */
#define VERBOSE KERN_ALERT "DBSYM: "
#else
#define VERBOSE
#endif

static inline int is_init(uint32_t opcode, struct ud *ud_obj)
{
	const ud_operand_t *op0 = ud_insn_opr(ud_obj, 0);
	const ud_operand_t *op1 = ud_insn_opr(ud_obj, 1);

	/* Needs to be a lea or mov */
	if (opcode != UD_Ilea && opcode != UD_Imov) {
		return 0;
	}

	/* Target is a register */
	if (op0->type != UD_OP_MEM ||
	/* Source is memory */
	    op1->type != UD_OP_REG) {
		return 0;
	}

	/* Expect positive index */
	if ((op0->base == UD_R_RSP && op0->index >= 0) ||
	/* Expect negative index */
	    (op0->base == UD_R_RBP && op0->index <= 0)) {
		return 1;
	}
	return 0;
}

static inline int is_rel_cond_jmp(uint32_t opcode, struct ud *ud_obj)
{
	switch (opcode) {
	case UD_Ijb:  case UD_Ijae:
	case UD_Ijbe: case UD_Ija:
	case UD_Ijl:  case UD_Ijge:
	case UD_Ijle: case UD_Ijg:
		return 1;
	}
	return 0;
}

static inline int is_cond_jmp(uint32_t opcode, struct ud *ud_obj)
{
	switch (opcode) {
	case UD_Ijo:  case UD_Ijno:
	case UD_Ijb:  case UD_Ijae:
	case UD_Ijz:  case UD_Ijnz:
	case UD_Ijbe: case UD_Ija:
	case UD_Ijs:  case UD_Ijns:
	case UD_Ijp:  case UD_Ijnp:
	case UD_Ijl:  case UD_Ijge:
	case UD_Ijle: case UD_Ijg:
		return 1;
	}
	return 0;
}

/* Interestingly enough, the kallsyms lookup is not always the same as
 * the compiled in symbol */
#define DECLARE_IS_FUNC_CALL(func, retcode) static inline int is_##func##_call(uintptr_t addr) { \
	static uintptr_t addr_##func = 0;				\
	if (addr_##func == 0) {						\
		addr_##func = kallsyms_lookup_name(""#func);		\
	}								\
	if (addr == addr_##func || addr == (uintptr_t)(& func))	{	\
		return retcode;						\
	}								\
	return 0;							\
}

DECLARE_IS_FUNC_CALL(kmalloc, KMALLOC)
DECLARE_IS_FUNC_CALL(__kmalloc, KMALLOC)
DECLARE_IS_FUNC_CALL(kzalloc, KZALLOC)
DECLARE_IS_FUNC_CALL(kfree, KFREE)

DECLARE_IS_FUNC_CALL(kmem_cache_alloc, KMEM_CACHE_ALLOC)
DECLARE_IS_FUNC_CALL(kmem_cache_free, KMEM_CACHE_FREE)

DECLARE_IS_FUNC_CALL(mutex_lock, MUTEX_LOCK)
DECLARE_IS_FUNC_CALL(_raw_spin_lock, SPIN_LOCK)
DECLARE_IS_FUNC_CALL(_raw_read_lock, READ_LOCK)
DECLARE_IS_FUNC_CALL(_raw_write_lock, WRITE_LOCK)
DECLARE_IS_FUNC_CALL(mutex_trylock, MUTEX_LOCK)
DECLARE_IS_FUNC_CALL(_raw_spin_trylock, SPIN_LOCK)
DECLARE_IS_FUNC_CALL(_raw_read_trylock, READ_LOCK)
DECLARE_IS_FUNC_CALL(_raw_write_trylock, WRITE_LOCK)

DECLARE_IS_FUNC_CALL(mutex_unlock, MUTEX_UNLOCK)
#ifdef CONFIG_INLINE_SPIN_UNLOCK
DECLARE_IS_FUNC_CALL(__raw_spin_unlock, SPIN_UNLOCK)
DECLARE_IS_FUNC_CALL(__raw_read_unlock, READ_UNLOCK)
DECLARE_IS_FUNC_CALL(__raw_write_unlock, WRITE_UNLOCK)
#else
DECLARE_IS_FUNC_CALL(_raw_spin_unlock, SPIN_UNLOCK)
DECLARE_IS_FUNC_CALL(_raw_read_unlock, READ_UNLOCK)
DECLARE_IS_FUNC_CALL(_raw_write_unlock, WRITE_UNLOCK)
#endif

static inline int is_alloc_call(uint32_t opcode, struct ud *ud_obj)
{
	/* Interestingly enough, the kallsyms lookup is not always the
	 * same as the compiled in symbol */
	const ud_operand_t *op0 = ud_insn_opr(ud_obj, 0);
	uintptr_t target = ud_obj->pc;
	int ret = NOT_CALL;

	if (opcode != UD_Icall) {
		return NOT_CALL;
	}

	target += op0->lval.sdword;

	if ((ret = is_kmalloc_call(target)) ||
	    (ret = is___kmalloc_call(target)) ||
	    (ret = is_kzalloc_call(target)) ||
	    (ret = is_kmem_cache_alloc_call(target)))
		return ret;
	return NOT_CALL;
}

static inline int is_free_call(uint32_t opcode, struct ud *ud_obj)
{
	const ud_operand_t *op0 = ud_insn_opr(ud_obj, 0);
	uintptr_t target = ud_obj->pc;
	int ret = 0;

	if (opcode != UD_Icall) {
		return NOT_CALL;
	}
	target += op0->lval.sdword;
	if ((ret = is_kfree_call(target)) ||
	    (ret = is_kmem_cache_free_call(target)))
		return ret;
	return NOT_CALL;
}

static inline int is_lock_call(uint32_t opcode, struct ud *ud_obj)
{
	const ud_operand_t *op0 = ud_insn_opr(ud_obj, 0);
	uintptr_t target = ud_obj->pc;
	int ret = 0;

	if (opcode != UD_Icall) {
		return NOT_CALL;
	}
	target += op0->lval.sdword;
	if ((ret = is_mutex_lock_call(target)) ||
	    (ret = is__raw_spin_lock_call(target)) ||
	    (ret = is__raw_read_lock_call(target)) ||
	    (ret = is__raw_write_lock_call(target)) ||
	    (ret = is_mutex_trylock_call(target)) ||
	    (ret = is__raw_spin_trylock_call(target)) ||
	    (ret = is__raw_read_trylock_call(target)) ||
	    (ret = is__raw_write_trylock_call(target)))
		return ret;
	return NOT_CALL;
}

static inline int is_unlock_call(uint32_t opcode, struct ud *ud_obj)
{
	const ud_operand_t *op0 = ud_insn_opr(ud_obj, 0);
	uintptr_t target = ud_obj->pc;
	int ret = 0;

	if (opcode != UD_Icall) {
		return NOT_CALL;
	}
	target += op0->lval.sdword;
	if ((ret = is_mutex_unlock_call(target)) ||
#ifndef CONFIG_INLINE_SPIN_UNLOCK
	    (ret = is__raw_spin_unlock_call(target)) ||
	    (ret = is__raw_read_unlock_call(target)) ||
	    (ret = is__raw_write_unlock_call(target))
#else
	    (ret = is___raw_spin_unlock_call(target)) ||
	    (ret = is___raw_read_unlock_call(target)) ||
	    (ret = is___raw_write_unlock_call(target))
#endif
	)
		return ret;
	return NOT_CALL;
}

/* NWT: fault injection routine only.
 * figure out start of function address given an address (off) in kernel text.
 * 	name = function name
 *	value = function address
 *  d = difference between off and function address
 * input is the desired address off and fault type
 * returns closest instruction address (if found), NULL otherwise
 */
unsigned long find_faulty_instr(db_expr_t off, int type, int *instr_len, int verbose)
{
	db_expr_t       d;
	char            *name;
	db_expr_t       value, cur_value, prev_value = 0;
	int		found = 0, _found = 0;
	static char name_buf[KSYM_NAME_LEN] = {0};
	char * mod_name = NULL;
	const char * sym_name = NULL;
	unsigned long sym_start;
	unsigned long sym_off;
	unsigned long sym_end;
	unsigned long sym_size;
	struct ud ud_obj;
	unsigned long insn_size;

	/* We need a bit more state */
	unsigned long early_target = 0;
	unsigned long early_size = 0;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);

	*instr_len = 0;
	sym_name = kallsyms_lookup(off, &sym_size, &sym_off, &mod_name, name_buf);
	if (sym_name == NULL) {
		printk(KERN_ERR "lookup: %lx: no sym name\n", off);
		return 0;
	}
	if (verbose > 1)
		printk(VERBOSE "Try to target %s in %s\n",
			sym_name, mod_name == NULL ? "kernel" : mod_name);
	sym_start = off - sym_off;
	sym_end = sym_start + sym_size;

	if (verbose > 1)
		printk(VERBOSE "Symbol: %lx -> %lx, off %lx\n",
			sym_start, sym_end, off);

	value = (db_expr_t) sym_start;
	d = sym_off;
	name = (char *) sym_name;
	if (name == 0) {
		value = off;
	}

	if (value >= DB_SMALL_VALUE_MIN && value <= DB_SMALL_VALUE_MAX) {
		printk(KERN_ERR "0x%lx: quit because addr is weird (%lx)\n", off, value);
		return 0;
	}

	if (name == 0 || d >= db_maxoff) {
		printk(KERN_ERR "0x%lx: quit because max off %lx\n", off, d);
		return 0 ;
	}
	/* 2) backup to start of function (SOF)
	 * 3) delineate instruction boundaries, find instruction length too.
	 */

	/* 4)  skip instructions until we get to our faulty address */
	cur_value = value;
	ud_set_pc(&ud_obj, cur_value);
	ud_set_input_buffer(&ud_obj, (void *)cur_value, sym_size);

	/* ML: This modifies the original behavior.  Instead of
	 * scanning the entire section in which the address was found,
	 * it only scans to the end of the symbol.
	 */
	while (!found && (insn_size = ud_disassemble(&ud_obj)) > 0) {
		const uint8_t *c = ud_insn_ptr(&ud_obj);
		uint32_t opcode = ud_insn_mnemonic(&ud_obj);
	redo: /* Sometimes this needs multi-instruction patterns */
		prev_value = cur_value;
		cur_value += insn_size;

		if (cur_value < off) {
			continue;
		}

		if (verbose > 1)
			printk(VERBOSE "%lx: %s\n", prev_value, ud_insn_hex(&ud_obj));

		/* 4a) bail out if instruction is leave (0xc9) */
		/*     Unless we're trying to inject a floating point fault */
		if (type != FLOAT_FAULT &&
		    (opcode == UD_Iret || opcode == UD_Iretf || opcode == UD_Ileave)) {
			if (verbose > 1)
				printk(VERBOSE "bailing out as we hit a leave\n");
			found = 0;
			break;
		}

		if (type == INIT_FAULT) {
			/* 5a) init fault: from SOF, look for movl $X, -Y(%ebp),
			 *     (C645Fxxx or C745Fxxx) and replace with nop.
			 *     x86-64: tends to use loaded effective
			 *     address from either rsp or rbp
			 */
			found = is_init(opcode, &ud_obj);
		} else if (type == NOP_FAULT) {
			/* 5b) nop*: replace instruction with nop */
			found = 1;
		} else if (type == DST_FAULT || type == SRC_FAULT) {
			/* 5c) dst/src: flip bits in mod/rm, sib, disp or imm fields */
			if (*c == 0x0f && insn_size > 2) {
				found = 1;
			} else if (*c != 0x0f && insn_size > 1) {
				found = 1;
			}
		} else if (type == INVERT_FAULT) {
			/* 5e) invert cond: search forward until we hit a Jxx or rep (F3 or F2).
			 *     replace instr with the negation of the condition.
			 */
			if (*c == 0xf2 || *c == 0xf3) {
				if (verbose > 1) printk(VERBOSE "found repX prefix\n");
				found = 1;
			} else if (opcode == UD_Iloopne || opcode == UD_Iloope || opcode == UD_Iloop) {
				if (verbose > 1) printk(VERBOSE "found loop\n");
				found = 1;
			} else if (is_cond_jmp(opcode, &ud_obj)) {
				/* look for jXX 8 (7X), loop,jcx (e0-3), jXX 16/32 (0f 8X) */
				if (verbose > 1) printk(VERBOSE "found rel jmp\n");
				found = 1;
			}
		} else if (type == BRANCH_FAULT) {
			/* 5e.1) nop cond: search forwrad until we hit a Jxx
			 *       and replace it with nop.
			 */
			if (opcode == UD_Iloopne || opcode == UD_Iloope || opcode == UD_Iloop) {
				if (verbose > 1) printk(VERBOSE "found loop\n");
				found = 1;
			} else if (is_cond_jmp(opcode, &ud_obj)) {
				/* look for jXX 8 (7X), loop,jcx (e0-3), jXX 16/32 (0f 8X) */
				if (verbose > 1) printk(VERBOSE "found rel jmp\n");
				found = 1;
			}
		} else if (type == OBO_FAULT) {
			/* 5e.2) off by one: search forward until we
			 *       hit a relative conditional branch
			 *       (<, <=, >, >=) and replace it so it's
			 *       off by one.
			 */
			found = is_rel_cond_jmp(opcode, &ud_obj);
		} else if (type == PTR_FAULT) {
			/* 5f) ptr: if instruction has regmodrm byte (i_has_modrm),
			 *     and mod field has address ([eyy]dispxx), eyy!=ebp
			 *     flip 1 bit in lower byte (0x0f) or any bit in following
			 *     bytes (sib, imm or disp).
			 */
			if (ud_obj.have_modrm) {
				if (((ud_obj.modrm >> 6) & 3) != 3 && (ud_obj.modrm & 7) != 5) {
					/* mod != 3 and rm != RBP */
					found = 1;
				}
			}
		} else if (type == INTERFACE_FAULT) {
			/* 5f) i/f: look for movl XX(rsp), reg or movb XX(rbp), reg,
			 *     where XX is positive. replace instr with nop.
			 *     movl=0x8a, movb=0x8b, mod=01XXX101 (disp8[ebp]), disp>0
			 */
			if (opcode == UD_Imov) {
				const ud_operand_t *op0 = ud_insn_opr(&ud_obj, 0);
				const ud_operand_t *op1 = ud_insn_opr(&ud_obj, 1);
				if ((op0->type == UD_OP_MEM && op0->base == UD_R_RBP && op0->index > 0) ||
				    (op1->type == UD_OP_MEM && op1->base == UD_R_RBP && op1->index > 0)) {
					if ((random() & 3) == 0) {
						if (verbose > 1) printk(VERBOSE "skipped...\n");
					} else {
						found = 1;
					}
				}
			}
		} else if (type == IRQ_FAULT) {
			/* 5g) irq: look for push reg or offset(reg) / popf,
			 *     where XX is positive. replace instr with nop.
			 *     movl=0x8a, movb=0x8b, mod=01XXX101 (disp8[ebp]), disp>0
			 */
			/* Relax this condition to anything dealing with eflags */
			if (opcode == UD_Ipush && *(uint8_t *)cur_value == 0x9d) {
				insn_size ++;
				found = 1;
			} else if (opcode == UD_Ipushfq) {
				int tmp_sz = ud_disassemble(&ud_obj);
				if (tmp_sz <= 0) break; /* There was nothing left to disassemble */
				opcode = ud_insn_mnemonic(&ud_obj);
				if (opcode != UD_Ipop) goto redo;
				insn_size += tmp_sz;
				found = 1;
			}
		} else if (type == INTRPT_FAULT) {
			/* 5h) int: look for cli or sti. replace instr
			 *     with nop.
			 */
			if (opcode == UD_Isti || opcode == UD_Icli) {
				found = 1;
			}
		} else if (type == BCOPY_FAULT) {
			/* 5i) cpy: look for an operation that moves
			 *     an immediate value into cx and a later
			 *     rep instruction.  Increase the
			 *     immediate value to overrun.
			 */
			if (!early_target) {
				if (opcode == UD_Imov) {
					const ud_operand_t *op0 = ud_insn_opr(&ud_obj, 0);
					const ud_operand_t *op1 = ud_insn_opr(&ud_obj, 1);
					if (op0->type == UD_OP_REG && op0->base == UD_R_RCX &&
					    op1->type == UD_OP_IMM) {
						early_size = insn_size;
						early_target = prev_value;
					}
				}
			} else {
				if (*c == 0xf2 || *c == 0xf3) {
					found = 1;
					prev_value = early_target;
					insn_size = early_size;
				}
			}
		} else if (type == FLOAT_FAULT) {
			/* 5j) flt: look the padding after the of a
			 *     function and shift the return down
			 *     enough to inject a faulty instruction.
			 *     In this case, inject an xmm operation.
			 */
			if (!early_target) {
				if (opcode == UD_Iret || opcode == UD_Iretf) {
					early_target = prev_value;
					early_size = insn_size;
				}
			} else if (opcode == UD_Inop) {
				early_size += insn_size;
				if (early_size > 5) {
					prev_value = early_target;
					insn_size = early_size;
					found = 1;
				}
			} else {
				found = 0;
				break;
			}
		} else if (type == VAR_FAULT) {
			/* 5k) var: look for matching sub and add rsp
			 *     and modify the immediates to allocate a
			 *     large stack object.
			 */
			const ud_operand_t *op0;
			const ud_operand_t *op1;
			if (!early_target) {
				if (opcode == UD_Isub) {
					op0 = ud_insn_opr(&ud_obj, 0);
					op1 = ud_insn_opr(&ud_obj, 1);
					if (op0->type == UD_OP_REG && op0->base == UD_R_RSP &&
					    op1->type == UD_OP_IMM && op1->size == 32) {
						early_target = prev_value;
						early_size = op1->lval.uqword;
					}
				}
			} else {
				if (opcode == UD_Iadd) {
					op0 = ud_insn_opr(&ud_obj, 0);
					op1 = ud_insn_opr(&ud_obj, 1);
					if (op0->type == UD_OP_REG && op0->base == UD_R_RSP &&
					    op1->type == UD_OP_IMM && op1->lval.uqword == early_size) {
						/* Found a matching add */
						uint8_t *c = (uint8_t *)prev_value;
						if (*c == 0x48) c++;
						if ((c[0] == 0x81 || c[0] == 0x83) && c[1] == 0xc4) {
							if (c[0] == 0x83) c[2] |= 0xf0;
							else c[3] += 0x04;
							_found = 1;
						}
					}
				}
			}
		} else if (type == ALLOC_FAULT || type == ALLOC_SZ_FAULT || type == BLOCKING_FAULT) {
			/* 5l.1) mem: look for a call to kmalloc,
			 *       kmem_cache_alloc, or kzalloc and
			 *       replace the call offset with a faulty
			 *       version
			 */
			int call_type = is_alloc_call(opcode, &ud_obj);
			if (call_type) {
				if (call_type != KMEM_CACHE_ALLOC || type != ALLOC_SZ_FAULT) {
					insn_size = (insn_size << 4) | (call_type & 0xf);
					found = 1;
				}
			}
		} else if (type == FREE_FAULT) {
			/* 5l.2) mem: look for a call kmalloc or kfree
			 *       and replace the call offset with a
			 *       faulty version of a similar function;
			 *       replace kmalloc to track allocations
			 *       and kfree to do an early free later
			 */
			int call_type;
			if ((call_type = is_alloc_call(opcode, &ud_obj)) ||
			    (call_type = is_free_call(opcode, &ud_obj))) {
				insn_size = (insn_size << 4) | (call_type & 0xf);
				found = 1;
			}
		} else if (type == MEM_LEAK_FAULT) {
			/* 5l.3) mem: look for a call to kfree or
			 *       kmem_cache_free and replace the call
			 *       offset with a faulty version
			 */
			if (is_free_call(opcode, &ud_obj)) {
				found = 1;
			}
		} else if (type == ATOMIC_FAULT) {
			/* 5m.1) lck: look for a call to
			 *       mutex|spin|read|write lock and
			 *       replace them with NOP
			 */
			if (is_lock_call(opcode, &ud_obj)) {
				found = 1;
			}
		} else if (type == UNLOCK_FAULT) {
			/* 5m.1) lck: look for a call to
			 *       mutex|spin|read|write unlock and
			 *       replace them with NOP
			 */
			if (is_unlock_call(opcode, &ud_obj)) {
				found = 1;
			}
		}
	}

	/* ML: This is a gross hack which sets the ip back to the
	 * initial sub %rsp for VAR_FAULT
	 */
	if (_found) {
		prev_value = early_target;
		found = 1;
		insn_size = 7;
	}
	/* if we're doing nop fault, then we're done.
	 */
	if (found) {
		*instr_len = insn_size;
		off = prev_value;
		if (verbose > 0)
			printk(VERBOSE "%s", name);
		else
			printk("%s", name);

		if (d)
			printk("+0x%lx: ", d);
		else
			printk(": ");
		/* printk(" @ %lx, ", value); */
		/* printk("instr @ %lx, len=%d\n", off, *instr_len); */
		return off;
	} else {
		if (verbose > 1)
			printk(KERN_ERR "cannot locate instruction in function, returning %lx\n", sym_end);
		*instr_len = 0;
		return sym_start + sym_size;
	}
}

/* ML: This continues disassembling until the end of the range. */
unsigned long find_faulty_instr_range(uintptr_t start, uintptr_t end,
				uintptr_t off, int type, int *instr_len,
				int verbose)
{
	do {
		if ((off = find_faulty_instr(off, type, instr_len, verbose)) >= end) {
			printk(KERN_ERR "cannot locate instruction in section\n");
			return 0;
		} else if (off == 0) {
			printk(KERN_ERR "some other error\n");
			return 0;
		}
	} while (*instr_len == 0);
	return off;
}
