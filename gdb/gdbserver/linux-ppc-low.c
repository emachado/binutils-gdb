/* GNU/Linux/PowerPC specific low level interface, for the remote server for
   GDB.
   Copyright (C) 1995-2013 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "server.h"
#include "linux-low.h"

#include <elf.h>
#include <asm/ptrace.h>

#include "gdb_proc_service.h"
#include "break-common.h"
#include "gdb_vecs.h"

/* These are in <asm/cputable.h> in current kernels.  */
#define PPC_FEATURE_HAS_VSX		0x00000080
#define PPC_FEATURE_HAS_ALTIVEC         0x10000000
#define PPC_FEATURE_HAS_SPE             0x00800000
#define PPC_FEATURE_CELL                0x00010000
#define PPC_FEATURE_BOOKE               0x00008000
#define PPC_FEATURE_HAS_DFP             0x00000400

/* These requests are used when the PowerPC HWDEBUG ptrace interface is
   available.  It exposes the debug facilities of PowerPC processors, as well
   as additional features of BookE processors, such as ranged breakpoints and
   watchpoints and hardware-accelerated condition evaluation.  */
#ifndef PPC_PTRACE_GETHWDBGINFO

/* Not having PPC_PTRACE_GETHWDBGINFO defined means that the PowerPC HWDEBUG 
   ptrace interface is not present in ptrace.h, so we'll have to pretty much
   include it all here so that the code at least compiles on older systems.  */
#define PPC_PTRACE_GETHWDBGINFO 0x89
#define PPC_PTRACE_SETHWDEBUG   0x88
#define PPC_PTRACE_DELHWDEBUG   0x87

struct ppc_debug_info
{
        uint32_t version;               /* Only version 1 exists to date.  */
        uint32_t num_instruction_bps;
        uint32_t num_data_bps;
        uint32_t num_condition_regs;
        uint32_t data_bp_alignment;
        uint32_t sizeof_condition;      /* size of the DVC register.  */
        uint64_t features;
};

/* Features will have bits indicating whether there is support for:  */
#define PPC_DEBUG_FEATURE_INSN_BP_RANGE         0x1
#define PPC_DEBUG_FEATURE_INSN_BP_MASK          0x2
#define PPC_DEBUG_FEATURE_DATA_BP_RANGE         0x4
#define PPC_DEBUG_FEATURE_DATA_BP_MASK          0x8

struct ppc_hw_breakpoint
{
        uint32_t version;               /* currently, version must be 1 */
        uint32_t trigger_type;          /* only some combinations allowed */
        uint32_t addr_mode;             /* address match mode */
        uint32_t condition_mode;        /* break/watchpoint condition flags */
        uint64_t addr;                  /* break/watchpoint address */
        uint64_t addr2;                 /* range end or mask */
        uint64_t condition_value;       /* contents of the DVC register */
};

/* Trigger type.  */
#define PPC_BREAKPOINT_TRIGGER_EXECUTE  0x1
#define PPC_BREAKPOINT_TRIGGER_READ     0x2
#define PPC_BREAKPOINT_TRIGGER_WRITE    0x4
#define PPC_BREAKPOINT_TRIGGER_RW       0x6

/* Address mode.  */
#define PPC_BREAKPOINT_MODE_EXACT               0x0
#define PPC_BREAKPOINT_MODE_RANGE_INCLUSIVE     0x1
#define PPC_BREAKPOINT_MODE_RANGE_EXCLUSIVE     0x2
#define PPC_BREAKPOINT_MODE_MASK                0x3

/* Condition mode.  */
#define PPC_BREAKPOINT_CONDITION_NONE   0x0
#define PPC_BREAKPOINT_CONDITION_AND    0x1
#define PPC_BREAKPOINT_CONDITION_EXACT  0x1
#define PPC_BREAKPOINT_CONDITION_OR     0x2
#define PPC_BREAKPOINT_CONDITION_AND_OR 0x3
#define PPC_BREAKPOINT_CONDITION_BE_ALL 0x00ff0000
#define PPC_BREAKPOINT_CONDITION_BE_SHIFT       16
#define PPC_BREAKPOINT_CONDITION_BE(n)  \
        (1<<((n)+PPC_BREAKPOINT_CONDITION_BE_SHIFT))
#endif /* PPC_PTRACE_GETHWDBGINFO */

/* Feature defined on Linux kernel v3.9: DAWR interface, that enables wider
   watchpoint (up to 512 bytes).  */
#ifndef PPC_DEBUG_FEATURE_DATA_BP_DAWR
#define PPC_DEBUG_FEATURE_DATA_BP_DAWR	0x10
#endif /* PPC_DEBUG_FEATURE_DATA_BP_DAWR */

/* We keep a list of break/watchpoints.  */
struct ppc_hw_point
{
  /* Address to break on, or to watch.  */
  CORE_ADDR addr;
  /* Length of the watchpoint.  */
  int len;
  /* Type of the break/watchpoint.  */
  enum target_hw_bp_type type;
  /* Flag to check if it is enabled.  */
  char enable;
  /* Number of registers used by the point. Embedded ppc476 for example can use
     2 registers to watch region larger than 8 bytes.  */
  int regs_used;
};

/* Maximum number of hardware watchpoints and breakpoints.  */
#define PPC_MAX_HW_POINTS 4

/* per-process arch-specific data we want to keep.  */
struct arch_process_info
{
  /* Current break/watchpoint requests for this process.  */
  struct ppc_hw_point hw_breakpoints[PPC_MAX_HW_POINTS];
  struct ppc_hw_point hw_watchpoints[PPC_MAX_HW_POINTS];
};

/* Per-thread arch-specific data we want to keep.  */
struct arch_lwp_info
{
  /* Break/watchpoints that should be added/removed.  */
  char hw_breakpoints_changed[PPC_MAX_HW_POINTS];
  char hw_watchpoints_changed[PPC_MAX_HW_POINTS];
  
  /* Cached stopped data address.  */
  CORE_ADDR stopped_data_address;

  /* Flag to check if this is a new thread.  */
  char is_new_thread;
};

static unsigned long ppc_hwcap;

/* Defined in auto-generated file powerpc-32l.c.  */
void init_registers_powerpc_32l (void);
extern const struct target_desc *tdesc_powerpc_32l;

/* Defined in auto-generated file powerpc-altivec32l.c.  */
void init_registers_powerpc_altivec32l (void);
extern const struct target_desc *tdesc_powerpc_altivec32l;

/* Defined in auto-generated file powerpc-cell32l.c.  */
void init_registers_powerpc_cell32l (void);
extern const struct target_desc *tdesc_powerpc_cell32l;

/* Defined in auto-generated file powerpc-vsx32l.c.  */
void init_registers_powerpc_vsx32l (void);
extern const struct target_desc *tdesc_powerpc_vsx32l;

/* Defined in auto-generated file powerpc-isa205-32l.c.  */
void init_registers_powerpc_isa205_32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_32l;

/* Defined in auto-generated file powerpc-isa205-altivec32l.c.  */
void init_registers_powerpc_isa205_altivec32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_altivec32l;

/* Defined in auto-generated file powerpc-isa205-vsx32l.c.  */
void init_registers_powerpc_isa205_vsx32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_vsx32l;

/* Defined in auto-generated file powerpc-e500l.c.  */
void init_registers_powerpc_e500l (void);
extern const struct target_desc *tdesc_powerpc_e500l;

/* Defined in auto-generated file powerpc-64l.c.  */
void init_registers_powerpc_64l (void);
extern const struct target_desc *tdesc_powerpc_64l;

/* Defined in auto-generated file powerpc-altivec64l.c.  */
void init_registers_powerpc_altivec64l (void);
extern const struct target_desc *tdesc_powerpc_altivec64l;

/* Defined in auto-generated file powerpc-cell64l.c.  */
void init_registers_powerpc_cell64l (void);
extern const struct target_desc *tdesc_powerpc_cell64l;

/* Defined in auto-generated file powerpc-vsx64l.c.  */
void init_registers_powerpc_vsx64l (void);
extern const struct target_desc *tdesc_powerpc_vsx64l;

/* Defined in auto-generated file powerpc-isa205-64l.c.  */
void init_registers_powerpc_isa205_64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_64l;

/* Defined in auto-generated file powerpc-isa205-altivec64l.c.  */
void init_registers_powerpc_isa205_altivec64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_altivec64l;

/* Defined in auto-generated file powerpc-isa205-vsx64l.c.  */
void init_registers_powerpc_isa205_vsx64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_vsx64l;

#define ppc_num_regs 73

/* This sometimes isn't defined.  */
#ifndef PT_ORIG_R3
#define PT_ORIG_R3 34
#endif
#ifndef PT_TRAP
#define PT_TRAP 40
#endif

#ifdef __powerpc64__
/* We use a constant for FPSCR instead of PT_FPSCR, because
   many shipped PPC64 kernels had the wrong value in ptrace.h.  */
static int ppc_regmap[] =
 {PT_R0 * 8,     PT_R1 * 8,     PT_R2 * 8,     PT_R3 * 8,
  PT_R4 * 8,     PT_R5 * 8,     PT_R6 * 8,     PT_R7 * 8,
  PT_R8 * 8,     PT_R9 * 8,     PT_R10 * 8,    PT_R11 * 8,
  PT_R12 * 8,    PT_R13 * 8,    PT_R14 * 8,    PT_R15 * 8,
  PT_R16 * 8,    PT_R17 * 8,    PT_R18 * 8,    PT_R19 * 8,
  PT_R20 * 8,    PT_R21 * 8,    PT_R22 * 8,    PT_R23 * 8,
  PT_R24 * 8,    PT_R25 * 8,    PT_R26 * 8,    PT_R27 * 8,
  PT_R28 * 8,    PT_R29 * 8,    PT_R30 * 8,    PT_R31 * 8,
  PT_FPR0*8,     PT_FPR0*8 + 8, PT_FPR0*8+16,  PT_FPR0*8+24,
  PT_FPR0*8+32,  PT_FPR0*8+40,  PT_FPR0*8+48,  PT_FPR0*8+56,
  PT_FPR0*8+64,  PT_FPR0*8+72,  PT_FPR0*8+80,  PT_FPR0*8+88,
  PT_FPR0*8+96,  PT_FPR0*8+104,  PT_FPR0*8+112,  PT_FPR0*8+120,
  PT_FPR0*8+128, PT_FPR0*8+136,  PT_FPR0*8+144,  PT_FPR0*8+152,
  PT_FPR0*8+160,  PT_FPR0*8+168,  PT_FPR0*8+176,  PT_FPR0*8+184,
  PT_FPR0*8+192,  PT_FPR0*8+200,  PT_FPR0*8+208,  PT_FPR0*8+216,
  PT_FPR0*8+224,  PT_FPR0*8+232,  PT_FPR0*8+240,  PT_FPR0*8+248,
  PT_NIP * 8,    PT_MSR * 8,    PT_CCR * 8,    PT_LNK * 8,
  PT_CTR * 8,    PT_XER * 8,    PT_FPR0*8 + 256,
  PT_ORIG_R3 * 8, PT_TRAP * 8 };
#else
/* Currently, don't check/send MQ.  */
static int ppc_regmap[] =
 {PT_R0 * 4,     PT_R1 * 4,     PT_R2 * 4,     PT_R3 * 4,
  PT_R4 * 4,     PT_R5 * 4,     PT_R6 * 4,     PT_R7 * 4,
  PT_R8 * 4,     PT_R9 * 4,     PT_R10 * 4,    PT_R11 * 4,
  PT_R12 * 4,    PT_R13 * 4,    PT_R14 * 4,    PT_R15 * 4,
  PT_R16 * 4,    PT_R17 * 4,    PT_R18 * 4,    PT_R19 * 4,
  PT_R20 * 4,    PT_R21 * 4,    PT_R22 * 4,    PT_R23 * 4,
  PT_R24 * 4,    PT_R25 * 4,    PT_R26 * 4,    PT_R27 * 4,
  PT_R28 * 4,    PT_R29 * 4,    PT_R30 * 4,    PT_R31 * 4,
  PT_FPR0*4,     PT_FPR0*4 + 8, PT_FPR0*4+16,  PT_FPR0*4+24,
  PT_FPR0*4+32,  PT_FPR0*4+40,  PT_FPR0*4+48,  PT_FPR0*4+56,
  PT_FPR0*4+64,  PT_FPR0*4+72,  PT_FPR0*4+80,  PT_FPR0*4+88,
  PT_FPR0*4+96,  PT_FPR0*4+104,  PT_FPR0*4+112,  PT_FPR0*4+120,
  PT_FPR0*4+128, PT_FPR0*4+136,  PT_FPR0*4+144,  PT_FPR0*4+152,
  PT_FPR0*4+160,  PT_FPR0*4+168,  PT_FPR0*4+176,  PT_FPR0*4+184,
  PT_FPR0*4+192,  PT_FPR0*4+200,  PT_FPR0*4+208,  PT_FPR0*4+216,
  PT_FPR0*4+224,  PT_FPR0*4+232,  PT_FPR0*4+240,  PT_FPR0*4+248,
  PT_NIP * 4,    PT_MSR * 4,    PT_CCR * 4,    PT_LNK * 4,
  PT_CTR * 4,    PT_XER * 4,    PT_FPSCR * 4,
  PT_ORIG_R3 * 4, PT_TRAP * 4
 };

static int ppc_regmap_e500[] =
 {PT_R0 * 4,     PT_R1 * 4,     PT_R2 * 4,     PT_R3 * 4,
  PT_R4 * 4,     PT_R5 * 4,     PT_R6 * 4,     PT_R7 * 4,
  PT_R8 * 4,     PT_R9 * 4,     PT_R10 * 4,    PT_R11 * 4,
  PT_R12 * 4,    PT_R13 * 4,    PT_R14 * 4,    PT_R15 * 4,
  PT_R16 * 4,    PT_R17 * 4,    PT_R18 * 4,    PT_R19 * 4,
  PT_R20 * 4,    PT_R21 * 4,    PT_R22 * 4,    PT_R23 * 4,
  PT_R24 * 4,    PT_R25 * 4,    PT_R26 * 4,    PT_R27 * 4,
  PT_R28 * 4,    PT_R29 * 4,    PT_R30 * 4,    PT_R31 * 4,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  PT_NIP * 4,    PT_MSR * 4,    PT_CCR * 4,    PT_LNK * 4,
  PT_CTR * 4,    PT_XER * 4,    -1,
  PT_ORIG_R3 * 4, PT_TRAP * 4
 };
#endif

static int
ppc_cannot_store_register (int regno)
{
  const struct target_desc *tdesc = current_process ()->tdesc;

#ifndef __powerpc64__
  /* Some kernels do not allow us to store fpscr.  */
  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE)
      && regno == find_regno (tdesc, "fpscr"))
    return 2;
#endif

  /* Some kernels do not allow us to store orig_r3 or trap.  */
  if (regno == find_regno (tdesc, "orig_r3")
      || regno == find_regno (tdesc, "trap"))
    return 2;

  return 0;
}

static int
ppc_cannot_fetch_register (int regno)
{
  return 0;
}

static void
ppc_collect_ptrace_register (struct regcache *regcache, int regno, char *buf)
{
  int size = register_size (regcache->tdesc, regno);

  memset (buf, 0, sizeof (long));

  if (size < sizeof (long))
    collect_register (regcache, regno, buf + sizeof (long) - size);
  else
    collect_register (regcache, regno, buf);
}

static void
ppc_supply_ptrace_register (struct regcache *regcache,
			    int regno, const char *buf)
{
  int size = register_size (regcache->tdesc, regno);
  if (size < sizeof (long))
    supply_register (regcache, regno, buf + sizeof (long) - size);
  else
    supply_register (regcache, regno, buf);
}


#define INSTR_SC        0x44000002
#define NR_spu_run      0x0116

/* If the PPU thread is currently stopped on a spu_run system call,
   return to FD and ADDR the file handle and NPC parameter address
   used with the system call.  Return non-zero if successful.  */
static int
parse_spufs_run (struct regcache *regcache, int *fd, CORE_ADDR *addr)
{
  CORE_ADDR curr_pc;
  int curr_insn;
  int curr_r0;

  if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int pc, r0, r3, r4;
      collect_register_by_name (regcache, "pc", &pc);
      collect_register_by_name (regcache, "r0", &r0);
      collect_register_by_name (regcache, "orig_r3", &r3);
      collect_register_by_name (regcache, "r4", &r4);
      curr_pc = (CORE_ADDR) pc;
      curr_r0 = (int) r0;
      *fd = (int) r3;
      *addr = (CORE_ADDR) r4;
    }
  else
    {
      unsigned long pc, r0, r3, r4;
      collect_register_by_name (regcache, "pc", &pc);
      collect_register_by_name (regcache, "r0", &r0);
      collect_register_by_name (regcache, "orig_r3", &r3);
      collect_register_by_name (regcache, "r4", &r4);
      curr_pc = (CORE_ADDR) pc;
      curr_r0 = (int) r0;
      *fd = (int) r3;
      *addr = (CORE_ADDR) r4;
    }

  /* Fetch instruction preceding current NIP.  */
  if ((*the_target->read_memory) (curr_pc - 4,
				  (unsigned char *) &curr_insn, 4) != 0)
    return 0;
  /* It should be a "sc" instruction.  */
  if (curr_insn != INSTR_SC)
    return 0;
  /* System call number should be NR_spu_run.  */
  if (curr_r0 != NR_spu_run)
    return 0;

  return 1;
}

static CORE_ADDR
ppc_get_pc (struct regcache *regcache)
{
  CORE_ADDR addr;
  int fd;

  if (parse_spufs_run (regcache, &fd, &addr))
    {
      unsigned int pc;
      (*the_target->read_memory) (addr, (unsigned char *) &pc, 4);
      return ((CORE_ADDR)1 << 63)
	| ((CORE_ADDR)fd << 32) | (CORE_ADDR) (pc - 4);
    }
  else if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int pc;
      collect_register_by_name (regcache, "pc", &pc);
      return (CORE_ADDR) pc;
    }
  else
    {
      unsigned long pc;
      collect_register_by_name (regcache, "pc", &pc);
      return (CORE_ADDR) pc;
    }
}

static void
ppc_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  CORE_ADDR addr;
  int fd;

  if (parse_spufs_run (regcache, &fd, &addr))
    {
      unsigned int newpc = pc;
      (*the_target->write_memory) (addr, (unsigned char *) &newpc, 4);
    }
  else if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int newpc = pc;
      supply_register_by_name (regcache, "pc", &newpc);
    }
  else
    {
      unsigned long newpc = pc;
      supply_register_by_name (regcache, "pc", &newpc);
    }
}


static int
ppc_get_hwcap (unsigned long *valp)
{
  const struct target_desc *tdesc = current_process ()->tdesc;
  int wordsize = register_size (tdesc, 0);
  unsigned char *data = alloca (2 * wordsize);
  int offset = 0;

  while ((*the_target->read_auxv) (offset, data, 2 * wordsize) == 2 * wordsize)
    {
      if (wordsize == 4)
	{
	  unsigned int *data_p = (unsigned int *)data;
	  if (data_p[0] == AT_HWCAP)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}
      else
	{
	  unsigned long *data_p = (unsigned long *)data;
	  if (data_p[0] == AT_HWCAP)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}

      offset += 2 * wordsize;
    }

  *valp = 0;
  return 0;
}

/* Forward declaration.  */
static struct usrregs_info ppc_usrregs_info;
#ifndef __powerpc64__
static int ppc_regmap_adjusted;
#endif

static void
ppc_arch_setup (void)
{
  const struct target_desc *tdesc;
#ifdef __powerpc64__
  long msr;
  struct regcache *regcache;

  /* On a 64-bit host, assume 64-bit inferior process with no
     AltiVec registers.  Reset ppc_hwcap to ensure that the
     collect_register call below does not fail.  */
  tdesc = tdesc_powerpc_64l;
  current_process ()->tdesc = tdesc;
  ppc_hwcap = 0;

  /* Only if the high bit of the MSR is set, we actually have
     a 64-bit inferior.  */
  regcache = new_register_cache (tdesc);
  fetch_inferior_registers (regcache, find_regno (tdesc, "msr"));
  collect_register_by_name (regcache, "msr", &msr);
  free_register_cache (regcache);
  if (msr < 0)
    {
      ppc_get_hwcap (&ppc_hwcap);
      if (ppc_hwcap & PPC_FEATURE_CELL)
	tdesc = tdesc_powerpc_cell64l;
      else if (ppc_hwcap & PPC_FEATURE_HAS_VSX)
	{
	  /* Power ISA 2.05 (implemented by Power 6 and newer processors)
	     increases the FPSCR from 32 bits to 64 bits. Even though Power 7
	     supports this ISA version, it doesn't have PPC_FEATURE_ARCH_2_05
	     set, only PPC_FEATURE_ARCH_2_06.  Since for now the only bits
	     used in the higher half of the register are for Decimal Floating
	     Point, we check if that feature is available to decide the size
	     of the FPSCR.  */
	  if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	    tdesc = tdesc_powerpc_isa205_vsx64l;
	  else
	    tdesc = tdesc_powerpc_vsx64l;
	}
      else if (ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC)
	{
	  if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	    tdesc = tdesc_powerpc_isa205_altivec64l;
	  else
	    tdesc = tdesc_powerpc_altivec64l;
	}

      current_process ()->tdesc = tdesc;
      return;
    }
#endif

  /* OK, we have a 32-bit inferior.  */
  tdesc = tdesc_powerpc_32l;
  current_process ()->tdesc = tdesc;

  ppc_get_hwcap (&ppc_hwcap);
  if (ppc_hwcap & PPC_FEATURE_CELL)
    tdesc = tdesc_powerpc_cell32l;
  else if (ppc_hwcap & PPC_FEATURE_HAS_VSX)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	tdesc = tdesc_powerpc_isa205_vsx32l;
      else
	tdesc = tdesc_powerpc_vsx32l;
    }
  else if (ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	tdesc = tdesc_powerpc_isa205_altivec32l;
      else
	tdesc = tdesc_powerpc_altivec32l;
    }

  /* On 32-bit machines, check for SPE registers.
     Set the low target's regmap field as appropriately.  */
#ifndef __powerpc64__
  if (ppc_hwcap & PPC_FEATURE_HAS_SPE)
    tdesc = tdesc_powerpc_e500l;

  if (!ppc_regmap_adjusted)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_SPE)
	ppc_usrregs_info.regmap = ppc_regmap_e500;

      /* If the FPSCR is 64-bit wide, we need to fetch the whole
	 64-bit slot and not just its second word.  The PT_FPSCR
	 supplied in a 32-bit GDB compilation doesn't reflect
	 this.  */
      if (register_size (tdesc, 70) == 8)
	ppc_regmap[70] = (48 + 2*32) * sizeof (long);

      ppc_regmap_adjusted = 1;
   }
#endif
  current_process ()->tdesc = tdesc;
}

/* Correct in either endianness.
   This instruction is "twge r2, r2", which GDB uses as a software
   breakpoint.  */
static const unsigned int ppc_breakpoint = 0x7d821008;
#define ppc_breakpoint_len 4

static int
ppc_breakpoint_at (CORE_ADDR where)
{
  unsigned int insn;

  if (where & ((CORE_ADDR)1 << 63))
    {
      char mem_annex[32];
      sprintf (mem_annex, "%d/mem", (int)((where >> 32) & 0x7fffffff));
      (*the_target->qxfer_spu) (mem_annex, (unsigned char *) &insn,
				NULL, where & 0xffffffff, 4);
      if (insn == 0x3fff)
	return 1;
    }
  else
    {
      (*the_target->read_memory) (where, (unsigned char *) &insn, 4);
      if (insn == ppc_breakpoint)
	return 1;
      /* If necessary, recognize more trap instructions here.  GDB only uses
	 the one.  */
    }

  return 0;
}

/* Provide only a fill function for the general register set.  ps_lgetregs
   will use this for NPTL support.  */

static void ppc_fill_gregset (struct regcache *regcache, void *buf)
{
  int i;

  for (i = 0; i < 32; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);

  for (i = 64; i < 70; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);

  for (i = 71; i < 73; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);
}

#ifndef PTRACE_GETVSXREGS
#define PTRACE_GETVSXREGS 27
#define PTRACE_SETVSXREGS 28
#endif

#define SIZEOF_VSXREGS 32*8

static void
ppc_fill_vsxregset (struct regcache *regcache, void *buf)
{
  int i, base;
  char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_VSX))
    return;

  base = find_regno (regcache->tdesc, "vs0h");
  for (i = 0; i < 32; i++)
    collect_register (regcache, base + i, &regset[i * 8]);
}

static void
ppc_store_vsxregset (struct regcache *regcache, const void *buf)
{
  int i, base;
  const char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_VSX))
    return;

  base = find_regno (regcache->tdesc, "vs0h");
  for (i = 0; i < 32; i++)
    supply_register (regcache, base + i, &regset[i * 8]);
}

#ifndef PTRACE_GETVRREGS
#define PTRACE_GETVRREGS 18
#define PTRACE_SETVRREGS 19
#endif

#define SIZEOF_VRREGS 33*16+4

static void
ppc_fill_vrregset (struct regcache *regcache, void *buf)
{
  int i, base;
  char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC))
    return;

  base = find_regno (regcache->tdesc, "vr0");
  for (i = 0; i < 32; i++)
    collect_register (regcache, base + i, &regset[i * 16]);

  collect_register_by_name (regcache, "vscr", &regset[32 * 16 + 12]);
  collect_register_by_name (regcache, "vrsave", &regset[33 * 16]);
}

static void
ppc_store_vrregset (struct regcache *regcache, const void *buf)
{
  int i, base;
  const char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC))
    return;

  base = find_regno (regcache->tdesc, "vr0");
  for (i = 0; i < 32; i++)
    supply_register (regcache, base + i, &regset[i * 16]);

  supply_register_by_name (regcache, "vscr", &regset[32 * 16 + 12]);
  supply_register_by_name (regcache, "vrsave", &regset[33 * 16]);
}

#ifndef PTRACE_GETEVRREGS
#define PTRACE_GETEVRREGS	20
#define PTRACE_SETEVRREGS	21
#endif

struct gdb_evrregset_t
{
  unsigned long evr[32];
  unsigned long long acc;
  unsigned long spefscr;
};

static void
ppc_fill_evrregset (struct regcache *regcache, void *buf)
{
  int i, ev0;
  struct gdb_evrregset_t *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE))
    return;

  ev0 = find_regno (regcache->tdesc, "ev0h");
  for (i = 0; i < 32; i++)
    collect_register (regcache, ev0 + i, &regset->evr[i]);

  collect_register_by_name (regcache, "acc", &regset->acc);
  collect_register_by_name (regcache, "spefscr", &regset->spefscr);
}

static void
ppc_store_evrregset (struct regcache *regcache, const void *buf)
{
  int i, ev0;
  const struct gdb_evrregset_t *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE))
    return;

  ev0 = find_regno (regcache->tdesc, "ev0h");
  for (i = 0; i < 32; i++)
    supply_register (regcache, ev0 + i, &regset->evr[i]);

  supply_register_by_name (regcache, "acc", &regset->acc);
  supply_register_by_name (regcache, "spefscr", &regset->spefscr);
}

static struct regset_info ppc_regsets[] = {
  /* List the extra register sets before GENERAL_REGS.  That way we will
     fetch them every time, but still fall back to PTRACE_PEEKUSER for the
     general registers.  Some kernels support these, but not the newer
     PPC_PTRACE_GETREGS.  */
  { PTRACE_GETVSXREGS, PTRACE_SETVSXREGS, 0, SIZEOF_VSXREGS, EXTENDED_REGS,
  ppc_fill_vsxregset, ppc_store_vsxregset },
  { PTRACE_GETVRREGS, PTRACE_SETVRREGS, 0, SIZEOF_VRREGS, EXTENDED_REGS,
    ppc_fill_vrregset, ppc_store_vrregset },
  { PTRACE_GETEVRREGS, PTRACE_SETEVRREGS, 0, 32 * 4 + 8 + 4, EXTENDED_REGS,
    ppc_fill_evrregset, ppc_store_evrregset },
  { 0, 0, 0, 0, GENERAL_REGS, ppc_fill_gregset, NULL },
  { 0, 0, 0, -1, -1, NULL, NULL }
};

static struct usrregs_info ppc_usrregs_info =
  {
    ppc_num_regs,
    ppc_regmap,
  };

static struct regsets_info ppc_regsets_info =
  {
    ppc_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct regs_info regs_info =
  {
    NULL, /* regset_bitmap */
    &ppc_usrregs_info,
    &ppc_regsets_info
  };

static const struct regs_info *
ppc_regs_info (void)
{
  return &regs_info;
}

/* Global structure that will store information about the available
   features provided by the PowerPC HWDEBUG ptrace interface.  */
static struct ppc_debug_info hwdebug_info;

/* Global variable that holds the maximum number of slots that the
   kernel will use.  This is only used when PowerPC HWDEBUG ptrace interface
   is available.  */
static size_t max_slots_number = 0;

struct hw_break_tuple
{
  long slot;
  struct ppc_hw_breakpoint *hw_break;
};

/* This is an internal VEC created to store information about *points inserted
   for each thread.  This is used when PowerPC HWDEBUG ptrace interface is
   available.  */
typedef struct thread_points
  {
    /* The TID to which this *point relates.  */
    int tid;
    /* Information about the *point, such as its address, type, etc.

       Each element inside this vector corresponds to a hardware
       breakpoint or watchpoint in the thread represented by TID.  The maximum
       size of these vector is MAX_SLOTS_NUMBER.  If the hw_break element of
       the tuple is NULL, then the position in the vector is free.  */
    struct hw_break_tuple *hw_breaks;
  } *thread_points_p;
DEF_VEC_P (thread_points_p);

VEC(thread_points_p) *ppc_threads = NULL;

/* The version of the PowerPC HWDEBUG kernel interface that we will use, if
   available.  */
#define PPC_DEBUG_CURRENT_VERSION 1

/* This function can be used to retrieve a thread_points by the TID of the
   related process/thread.  If nothing has been found, and ALLOC_NEW is 0,
   it returns NULL.  If ALLOC_NEW is non-zero, a new thread_points for the
   provided TID will be created and returned.  */
static struct thread_points *
hwdebug_find_thread_points_by_tid (int tid, int alloc_new)
{
  int i;
  struct thread_points *t;

  for (i = 0; VEC_iterate (thread_points_p, ppc_threads, i, t); i++)
    if (t->tid == tid)
      return t;

  t = NULL;

  /* Do we need to allocate a new point_item
     if the wanted one does not exist?  */
  if (alloc_new)
    {
      t = xmalloc (sizeof (struct thread_points));
      t->hw_breaks
	= xzalloc (max_slots_number * sizeof (struct hw_break_tuple));
      t->tid = tid;
      VEC_safe_push (thread_points_p, ppc_threads, t);
    }

  return t;
}


static void
ppc_hwdebug_insert_point (struct ppc_hw_breakpoint *b, int tid)
{
  int i;
  long slot;
  struct ppc_hw_breakpoint *p = xmalloc (sizeof (struct ppc_hw_breakpoint));
  struct hw_break_tuple *hw_breaks;
  struct thread_points *t;

  memcpy (p, b, sizeof (struct ppc_hw_breakpoint));

  errno = 0;
  slot = ptrace (PPC_PTRACE_SETHWDEBUG, tid, 0, p);
  if (slot < 0)
    perror_with_name (_("Unexpected error setting breakpoint or watchpoint"));

  /* Everything went fine, so we have to register this *point.  */
  t = hwdebug_find_thread_points_by_tid (tid, 1);
  
  if (t == NULL)
    {
      /* FIXME had to remove cleanup() support for gdbserver and ended up with
         this manual cleanup */
      xfree (p);
      gdb_assert(t != NULL);
    }

  hw_breaks = t->hw_breaks;

  /* Find a free element in the hw_breaks vector.  */
  for (i = 0; i < max_slots_number; i++)
    if (hw_breaks[i].hw_break == NULL)
      {
	hw_breaks[i].slot = slot;
	hw_breaks[i].hw_break = p;
	break;
      }

  if (i == max_slots_number)
    {
      /* FIXME */
      xfree(p);
      gdb_assert (i != max_slots_number);
    }
}

/* This function compares two ppc_hw_breakpoint structs field-by-field.  */
static int
hwdebug_point_cmp (struct ppc_hw_breakpoint *a, struct ppc_hw_breakpoint *b)
{
  return (a->trigger_type == b->trigger_type
	  && a->addr_mode == b->addr_mode
	  && a->condition_mode == b->condition_mode
	  && a->addr == b->addr
	  && a->addr2 == b->addr2
	  && a->condition_value == b->condition_value);
}

/* This function is a generic wrapper that is responsible for removing a
   *point (i.e., calling `ptrace' in order to issue the request to the
   kernel), and unregistering it internally at GDB.  */
void
ppc_hwdebug_remove_point (struct ppc_hw_breakpoint *b, int tid)
{
  int i;
  struct hw_break_tuple *hw_breaks;
  struct thread_points *t;

  t = hwdebug_find_thread_points_by_tid (tid, 0);
  gdb_assert (t != NULL);
  hw_breaks = t->hw_breaks;

  for (i = 0; i < max_slots_number; i++)
    if (hw_breaks[i].hw_break && hwdebug_point_cmp (hw_breaks[i].hw_break, b))
      break;

  gdb_assert (i != max_slots_number);

  /* We have to ignore ENOENT errors because the kernel implements hardware
     breakpoints/watchpoints as "one-shot", that is, they are automatically
     deleted when hit.  */
  errno = 0;
  if (ptrace (PPC_PTRACE_DELHWDEBUG, tid, 0, hw_breaks[i].slot) < 0)
    if (errno != ENOENT)
      perror_with_name (_("Unexpected error deleting "
			  "breakpoint or watchpoint"));

  xfree (hw_breaks[i].hw_break);
  hw_breaks[i].hw_break = NULL;
}

/* Returns non-zero if we support the PowerPC HWDEBUG ptrace interface.  */
static int
have_ptrace_hwdebug_interface (void)
{
  static int have_ptrace_hwdebug_interface = -1;

  if (have_ptrace_hwdebug_interface == -1)
    {
      int tid;

      tid = ptid_get_lwp (current_ptid);
      if (tid == 0)
	tid = ptid_get_pid (current_ptid);

      /* Check for kernel support for PowerPC HWDEBUG ptrace interface.  */
      if (ptrace (PPC_PTRACE_GETHWDBGINFO, tid, 0, &hwdebug_info) >= 0)
	{
	  /* Check whether PowerPC HWDEBUG ptrace interface is functional and
	     provides any supported feature.  */
	  if (hwdebug_info.features != 0)
	    {
	      have_ptrace_hwdebug_interface = 1;
	      max_slots_number = hwdebug_info.num_instruction_bps
	        + hwdebug_info.num_data_bps
	        + hwdebug_info.num_condition_regs;
	      return have_ptrace_hwdebug_interface;
	    }
	}
      /* Old school interface and no PowerPC HWDEBUG ptrace support.  */
      have_ptrace_hwdebug_interface = 0;
      memset (&hwdebug_info, 0, sizeof (struct ppc_debug_info));
    }

  return have_ptrace_hwdebug_interface;
}

/* Returns a value to set hw watchpoint on DABR interface.  */
long
ppc_linux_create_dabr_value (CORE_ADDR addr, int len, int rw)
{
  long dabr_value;
  long read_mode, write_mode;

  if (ppc_hwcap & PPC_FEATURE_BOOKE)
    {
      /* PowerPC 440 requires only the read/write flags to be passed
	 to the kernel.  */
      read_mode = 1;
      write_mode = 2;
    }
  else
    {
      /* PowerPC 970 and other DABR-based processors are required to pass
	 the Breakpoint Translation bit together with the flags.  */
      read_mode = 5;
      write_mode = 6;
    }

  dabr_value = addr & ~(read_mode | write_mode);
  switch (rw)
    {
    case hw_read:
      /* Set read and translate bits.  */
      dabr_value |= read_mode;
      break;
    case hw_write:
      /* Set write and translate bits.  */
      dabr_value |= write_mode;
      break;
    case hw_access:
      /* Set read, write and translate bits.  */
      dabr_value |= read_mode | write_mode;
      break;
    }

  return dabr_value;
}

/* Fills struct ppc_hw_breakpoint to insert/remove hw breakpoints. For 'len'
   bigger than zero, sets ranged breakpoint. In case of 'len' equals zero, set
   a normal hw breakpoint.  */
void
ppc_linux_create_hw_breakpoint_request (CORE_ADDR addr, int len,
					struct ppc_hw_breakpoint *p)
{
  p->version = PPC_DEBUG_CURRENT_VERSION;
  p->trigger_type = PPC_BREAKPOINT_TRIGGER_EXECUTE;
  p->condition_mode = PPC_BREAKPOINT_CONDITION_NONE;
  p->addr = (uint64_t) addr;
  p->condition_value = 0;

  if (len)
    {
      p->addr_mode = PPC_BREAKPOINT_MODE_RANGE_INCLUSIVE;

      /* The breakpoint will trigger if the address of the instruction is
	 within the defined range, as follows: p.addr <= address < p.addr2.  */
      p->addr2 = (uint64_t) addr + len;
    }
  else
    {
      p->addr_mode = PPC_BREAKPOINT_MODE_EXACT;
      p->addr2 = 0;
    }
}

/* Insert hw watchpoint on DABR interface.  */
int
ppc_dabr_insert_point (long dabr_value, int tid)
{
  if (ptrace (PTRACE_SET_DEBUGREG, tid, 0, dabr_value) < 0)
    return -1;
  return 0;
}

/* Remove hw watchpoint on DABR interface.  */
int
ppc_dabr_remove_point (int tid)
{
  if (ptrace (PTRACE_SET_DEBUGREG, tid, 0, 0) < 0)
    return -1;
  return 0;
}

int
ppc_linux_insert_hw_break (CORE_ADDR addr, int tid)
{
  struct ppc_hw_breakpoint p;

  if (!have_ptrace_hwdebug_interface ())
    return -1;

  ppc_linux_create_hw_breakpoint_request (addr, 0, &p);

  ppc_hwdebug_insert_point (&p, tid);

  return 0;
}

int
ppc_linux_remove_hw_break (CORE_ADDR addr, int tid)
{
  struct ppc_hw_breakpoint p;

  if (!have_ptrace_hwdebug_interface ())
    return -1;

  ppc_linux_create_hw_breakpoint_request (addr, 0, &p);

  ppc_hwdebug_remove_point (&p, tid);

  return 0;
}

/* Fills struct ppc_hw_breakpoint to insert/remove simple hw watchpoint for
   HWDEBUG ptrace interface.  */
static void
ppc_linux_create_hwdebug_watchpoint_request (CORE_ADDR addr, int len,
					     enum target_hw_bp_type type,
					     struct ppc_hw_breakpoint *p)
{
  gdb_assert (have_ptrace_hwdebug_interface ());

  if (len == 1
      || !(hwdebug_info.features & PPC_DEBUG_FEATURE_DATA_BP_RANGE))
    {
      p->condition_mode = PPC_BREAKPOINT_CONDITION_NONE;
      p->condition_value = 0;
      p->addr_mode = PPC_BREAKPOINT_MODE_EXACT;
      p->addr2 = 0;
    }
  else
    {
      p->addr_mode = PPC_BREAKPOINT_MODE_RANGE_INCLUSIVE;
      p->condition_mode = PPC_BREAKPOINT_CONDITION_NONE;
      p->condition_value = 0;

      /* The watchpoint will trigger if the address of the memory access is
	 within the defined range, as follows: p->addr <= address < p->addr2.

	 Note that the above sentence just documents how ptrace interprets
	 its arguments; the watchpoint is set to watch the range defined by
	 the user _inclusively_, as specified by the user interface.  */
      p->addr2 = (uint64_t) addr + len;
    }

  p->version = PPC_DEBUG_CURRENT_VERSION;

  if (type == hw_read)
    p->trigger_type = PPC_BREAKPOINT_TRIGGER_READ;
  else if (type == hw_write)
    p->trigger_type = PPC_BREAKPOINT_TRIGGER_WRITE;
  else /* access watchpoint */
    p->trigger_type = PPC_BREAKPOINT_TRIGGER_READ | PPC_BREAKPOINT_TRIGGER_WRITE;

  p->addr = (uint64_t) addr;
}

/* Insert hw watchpoint, checking which interface is available (DABR or
   HWDEBUG). */
int
ppc_linux_insert_hw_watch (CORE_ADDR addr, int len, enum target_hw_bp_type type,
			   int tid)
{
  long dabr_value;

  if (have_ptrace_hwdebug_interface ())
    {
      struct ppc_hw_breakpoint p;

      ppc_linux_create_hwdebug_watchpoint_request (addr, len, type, &p); 

      ppc_hwdebug_insert_point (&p, tid);

      return 0;
    }

  dabr_value = ppc_linux_create_dabr_value (addr, len, type);

  if (ppc_dabr_insert_point (dabr_value, tid) < 0)
    return -1;

  return 0;
}

/* Remove hw watchpoint, checking which interface is available (DABR or
   HWDEBUG). Used by gdbserver.  */
int
ppc_linux_remove_hw_watch (CORE_ADDR addr, int len,
			   enum target_hw_bp_type type, int tid)
{
  if (have_ptrace_hwdebug_interface ())
    {
      struct ppc_hw_breakpoint p;

      ppc_linux_create_hwdebug_watchpoint_request (addr, len, type, &p); 

      ppc_hwdebug_remove_point (&p, tid);

      return 0;
    }

  if (ppc_dabr_remove_point (tid) < 0)
    return -1;

  return 0;
}


/* Returns the number of hw breakpoints provided by processor.  */
static int
ppc_linux_get_hw_breakpoint_count (void)
{
  if (have_ptrace_hwdebug_interface ())
    /* When PowerPC HWDEBUG ptrace interface is available, the number of
       available hardware breakpoints is stored at the hwdebug_info struct.  */
    return hwdebug_info.num_instruction_bps;

  /* When we do not have PowerPC HWDEBUG ptrace interface, we should
     consider having no hardware breakpoints.  */
  return 0;
}

/* Returns the number of hw watchpoints provided by processor.  */
static int
ppc_linux_get_hw_watchpoint_count (void)
{
  if (have_ptrace_hwdebug_interface ())
    /* When PowerPC HWDEBUG ptrace interface is available, the number of
       available hardware watchpoints is stored at hwdebug_info struct.  */
    return hwdebug_info.num_data_bps;

  /* When we do not have PowerPC HWDEBUG ptrace interface, we should
     consider having 1 hardware watchpoint.  */
  return 1;
}

int ppc_linux_check_hw_breakpoint_availability (CORE_ADDR addr)
{
  return ((ppc_linux_get_hw_breakpoint_count() > 0) ? 1 : 0);
}

int ppc_linux_check_hw_watchpoint_availability (CORE_ADDR addr, int len)
{
  /* Handle sub-8-byte quantities.  */
  if (len <= 0)
    return 0;

  /* The PowerPC HWDEBUG ptrace interface tells if there are alignment
     restrictions for watchpoints in the processors.  In that case, we use that
     information to determine the hardcoded watchable region for
     watchpoints.  */
  if (have_ptrace_hwdebug_interface ())
    {
      int region_size;
      /* Embedded DAC-based processors, like the PowerPC 440 have ranged
	 watchpoints and can watch any access within an arbitrary memory
	 region. This is useful to watch arrays and structs, for instance.  It
         takes two hardware watchpoints though.  */
      if (len > 1
	  && hwdebug_info.features & PPC_DEBUG_FEATURE_DATA_BP_RANGE
	  && ppc_hwcap & PPC_FEATURE_BOOKE)
	return 2;
      /* Check if the processor provides DAWR interface.  */
      if (hwdebug_info.features & PPC_DEBUG_FEATURE_DATA_BP_DAWR)
	/* DAWR interface allows to watch up to 512 byte wide ranges which
	   can't cross a 512 byte boundary.  */
	region_size = 512;
      else
	region_size = hwdebug_info.data_bp_alignment;
      /* Server processors provide one hardware watchpoint and addr+len should
         fall in the watchable region provided by the ptrace interface.  */
      if (region_size
	  && (addr + len > (addr & ~(region_size - 1)) + region_size))
	return 0;
    }
  /* addr+len must fall in the 8 byte watchable region for DABR-based
     processors (i.e., server processors).  Without the new PowerPC HWDEBUG 
     ptrace interface, DAC-based processors (i.e., embedded processors) will
     use addresses aligned to 4-bytes due to the way the read/write flags are
     passed in the old ptrace interface.  */
  else if (((ppc_hwcap & PPC_FEATURE_BOOKE)
	   && (addr + len) > (addr & ~3) + 4)
	   || (addr + len) > (addr & ~7) + 8)
    return 0;

  return 1;
}

/* Mark the watch registers of lwp, represented by ENTRY, as changed,
   if the lwp's process id is *PID_P.  */
struct update_registers_data
{
  char is_breakpoint;
  int i;
};

static int
update_registers_callback (struct inferior_list_entry *entry,
				 void *arg)
{
  struct lwp_info *lwp = (struct lwp_info *) entry;
  struct update_registers_data *data = (struct update_registers_data *) arg;

  /* Only update the threads of the current process.  */
  if (pid_of (lwp) == pid_of (get_thread_lwp (current_inferior)))
    {
      /* The actual update is done later just before resuming the lwp,
         we just mark that the break/watchpoints need updating.  */
      if (data->is_breakpoint)
	  lwp->arch_private->hw_breakpoints_changed[data->i] = 1;
      else
	  lwp->arch_private->hw_watchpoints_changed[data->i] = 1;

      /* If the lwp isn't stopped, force it to momentarily pause, so
	 we can update its debug registers.  */
      if (!lwp->stopped)
	linux_stop_lwp (lwp);
    }

  return 0;
}

/* Translate breakpoint type TYPE in rsp to 'enum target_hw_bp_type'.  */
static enum target_hw_bp_type
rsp_bp_type_to_target_hw_bp_type (char type)
{
  switch (type)
    {
    case '1':
      return hw_execute;
    case '2':
      return hw_write;
    case '3':
      return hw_read;
    case '4':
      return hw_access;
    }

  gdb_assert_not_reached ("unhandled RSP breakpoint type");
}

/* Verify if the break/watchpoint parameters are ok to be inserted.  */
static int
ppc_initialize_hw_point (CORE_ADDR addr, int len,
			   enum target_hw_bp_type type,
			   struct ppc_hw_point *hw_point)
{
  int regs_used;

  if (type == hw_execute)
    {
      /* Check if the settings are ok for a breakpoint.  */
      if ((regs_used = ppc_linux_check_hw_breakpoint_availability (addr)) < 0)
	/* Unsupported.  */
	return -2;
    }
  else
    {
      /* Check if the settings are ok for a watchpoint.  */
      if ((regs_used = ppc_linux_check_hw_watchpoint_availability (addr, len)) < 0)
	/* Unsupported.  */
	return -2;
    }

  hw_point->addr = addr;
  hw_point->len = len;
  hw_point->type = type;
  hw_point->enable = 1;
  hw_point->regs_used = regs_used;

  return 0;
}

/* Adds break/watchpoint to the list of the process.  */
static int
ppc_add_hw_point_to_list (struct ppc_hw_point new_hw_point)
{
  struct process_info *proc = current_process ();
  struct ppc_hw_point *hw_points;
  int i, max_points;
  char is_breakpoint = (new_hw_point.type == hw_execute);

  if (is_breakpoint)
    {
      /* retrieving info about breakpoints.  */
      hw_points = proc->private->arch_private->hw_breakpoints;
      max_points = ppc_linux_get_hw_breakpoint_count ();
    }
  else
    {
      /* retrieving info about watchpoints.  */
      hw_points = proc->private->arch_private->hw_watchpoints;
      max_points = ppc_linux_get_hw_watchpoint_count ();
    } 

  gdb_assert (max_points <= PPC_MAX_HW_POINTS);

  /* Add to the list of breakpoints.  */
  for (i = 0; i < max_points; i++)
    if (!hw_points[i].enable)
      {
	struct update_registers_data arg = { is_breakpoint, i};
	hw_points[i] = new_hw_point;
	find_inferior (&all_lwps, update_registers_callback, &arg);
	return 0;
      }

  /* No free slot available for hw break/watchpoint.  */
  return -1;
}

/* Adds break/watchpoint to the list of the process.  */
static int
ppc_remove_hw_point_from_list (struct ppc_hw_point hw_point)
{
  struct process_info *proc = current_process ();
  struct ppc_hw_point *hw_points;
  int i, max_points;
  char is_breakpoint = (hw_point.type == hw_execute);

  if (is_breakpoint)
    {
      /* retrieving info about breakpoints.  */
      hw_points = proc->private->arch_private->hw_breakpoints;
      max_points = ppc_linux_get_hw_breakpoint_count ();
    }
  else
    {
      /* retrieving info about watchpoints.  */
      hw_points = proc->private->arch_private->hw_watchpoints;
      max_points = ppc_linux_get_hw_watchpoint_count ();
    } 

  gdb_assert (max_points <= PPC_MAX_HW_POINTS);

  for (i = 0; i < max_points; i++)
    /* Search for an equal hw_point in the list.  */
    if (hw_points[i].addr == hw_point.addr
	&& hw_points[i].len == hw_point.len
	&& hw_points[i].type == hw_point.type)
      {
	struct update_registers_data arg = { is_breakpoint, i};
	/* Mark to be removed.  */
	hw_points[i].enable = 0;
	find_inferior (&all_lwps, update_registers_callback, &arg);
	return 0;
      }

  gdb_assert_not_reached ("Cannot find hw breakpoint or watchpoint to remove");
  return -1;
}

/* Insert a break or watchpoint. Returns 0 on success, -1 on failure and 1 on
   unsupported.  */
static int
ppc_insert_point (char type, CORE_ADDR addr, int len)
{
  enum target_hw_bp_type hw_point_type;
  struct ppc_hw_point new_hw_point;

  /* Breakpoint/watchpoint types:
     '0' - software-breakpoint (not supported)
     '1' - hardware-breakpoint (only on embedded)
     '2' - write watchpoint (supported)
     '3' - read watchpoint (supported)
     '4' - access watchpoint (supported).  */

  if (((ppc_linux_get_hw_breakpoint_count() > 0) && (type < '1' || type > '4'))
      || (type < '2' || type > '4'))
	/* Unsupported.  */
	return 1;

  hw_point_type = rsp_bp_type_to_target_hw_bp_type (type);

  if (ppc_initialize_hw_point (addr, len, hw_point_type, &new_hw_point) < 0)
    /* Unsupported.  */
    return 1;

  if (ppc_add_hw_point_to_list (new_hw_point) < 0)
    return -1;

  return 0;
}

/* Remove a break or watchpoint. Returns 0 on success, -1 on failure and 1 on
   unsupported.  */
static int
ppc_remove_point (char type, CORE_ADDR addr, int len)
{
  struct ppc_hw_point hw_point;

  if (((ppc_linux_get_hw_breakpoint_count() > 0) && (type < '1' || type > '4'))
      || (type < '2' || type > '4'))
    /* Unsupported.  */
    return 1;
  
  hw_point.addr = addr;
  hw_point.len = len;
  hw_point.type = rsp_bp_type_to_target_hw_bp_type (type); 

  if (ppc_remove_hw_point_from_list (hw_point) < 0)
    return -1;

  return 0;
}

/* Return whether current thread is stopped due to a watchpoint.  */
static int
ppc_stopped_by_watchpoint (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_inferior);
  siginfo_t siginfo;

  /* Retrieve siginfo.  */
  errno = 0;
  if (ptrace (PTRACE_GETSIGINFO, lwpid_of (lwp), 0, &siginfo) < 0)
    {
      perror_with_name ("Unexpected error issuing PTRACE_GETSIGINFO");
      return 0;
    }

  /* This must be a hardware breakpoint.  */
  if (siginfo.si_signo != SIGTRAP
      || (siginfo.si_code & 0xffff) != 0x0004 /* TRAP_HWBKPT */)
    return 0;

  /* Cache stopped data address for use by ppc_stopped_data_address.  */
  lwp->arch_private->stopped_data_address = (CORE_ADDR) (uintptr_t) siginfo.si_addr;

  return 1;
}

/* Return data address that triggered watchpoint.  Called only if
   ppc_linux_stopped_by_watchpoint returned true.  */
static CORE_ADDR
ppc_stopped_data_address (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_inferior);

  /* Return cached stopped data address retrieved on
     ppc_stopped_by_watchpoint.  */
  return lwp->arch_private->stopped_data_address;
}

static struct arch_process_info *
ppc_new_process (void)
{
  struct arch_process_info *proc = xcalloc (1, sizeof (struct arch_process_info));
  return proc;
}

/* Called when a new thread is detected.  */
static struct arch_lwp_info *
ppc_new_thread (void)
{
  struct arch_lwp_info *lwp = xcalloc (1, sizeof (struct arch_lwp_info));

  /* Mark as new thread.  */
  lwp->is_new_thread = 1;

  return lwp;
}

/* Called when resuming a thread.
   If the break/watchpoints have changed, update the thread's copies.  */
static void
ppc_prepare_to_resume (struct lwp_info *lwp)
{
  int tid = lwpid_of (lwp);
  struct process_info *proc = find_process_pid (pid_of (lwp));
  struct arch_process_info *proc_info = proc->private->arch_private;
  struct arch_lwp_info *lwp_info = lwp->arch_private;
  int i;

  /* Check if this is a new thread in order to set all the valid hw points.  */
  if (lwp_info->is_new_thread)
    {
      for (i = 0; i < ppc_linux_get_hw_breakpoint_count (); i++)
	{
	  if (proc_info->hw_breakpoints[i].enable)
	    lwp_info->hw_breakpoints_changed[i] = 1;
	}

      for (i = 0; i < ppc_linux_get_hw_watchpoint_count (); i++)
	{
	  if (proc_info->hw_watchpoints[i].enable)
	    lwp_info->hw_watchpoints_changed[i] = 1;
	}

      lwp_info->is_new_thread = 0;
    }

  for (i = 0; i < ppc_linux_get_hw_breakpoint_count (); i++)
    {
      /* Looking for breakpoints to update.  */
      if (lwp_info->hw_breakpoints_changed[i])
	{
	  if (proc_info->hw_breakpoints[i].enable)
	    {
	      /* Insert the breakpoint.  */
	      if (ppc_linux_insert_hw_break (proc_info->hw_breakpoints[i].addr,
					     tid) < 0)
		perror_with_name ("Unexpected error when inserting breakpoint");
	    }
	  else
	    {
	      /* Remove the breakpoint.  */
	      if (ppc_linux_remove_hw_break (proc_info->hw_breakpoints[i].addr,
					     tid) < 0)
		perror_with_name ("Unexpected error when removing breakpoint");
	    }

	  lwp_info->hw_breakpoints_changed[i] = 0;
	}
    }
      
  for (i = 0; i < ppc_linux_get_hw_watchpoint_count (); i++)
    {
      /* Looking for watchpoints to update.  */
      if (lwp_info->hw_watchpoints_changed[i])
	{
	  if (proc_info->hw_watchpoints[i].enable)
	    {
	      /* Insert the watchpoint.  */
	      if (ppc_linux_insert_hw_watch (proc_info->hw_watchpoints[i].addr,
					     proc_info->hw_watchpoints[i].len,
					     proc_info->hw_watchpoints[i].type,
					     tid) < 0)
		perror_with_name ("Unexpected error when inserting watchpoint");
	    }
	  else
	    {
	      /* Remove the watchpoint.  */
	      if (ppc_linux_remove_hw_watch (proc_info->hw_watchpoints[i].addr,
					     proc_info->hw_watchpoints[i].len,
					     proc_info->hw_watchpoints[i].type,
					     tid) < 0)
		perror_with_name ("Unexpected error when removing watchpoint");
	    }

	  lwp_info->hw_watchpoints_changed[i] = 0;
	}
    }
}

struct linux_target_ops the_low_target = {
  ppc_arch_setup,
  ppc_regs_info,
  ppc_cannot_fetch_register,
  ppc_cannot_store_register,
  NULL, /* fetch_register */
  ppc_get_pc,
  ppc_set_pc,
  (const unsigned char *) &ppc_breakpoint,
  ppc_breakpoint_len,
  NULL,
  0,
  ppc_breakpoint_at,
  ppc_insert_point,
  ppc_remove_point,
  ppc_stopped_by_watchpoint,
  ppc_stopped_data_address,
  ppc_collect_ptrace_register,
  ppc_supply_ptrace_register,
  NULL, /* siginfo_fixup */
  ppc_new_process,
  ppc_new_thread,
  ppc_prepare_to_resume
};

void
initialize_low_arch (void)
{
  /* Initialize the Linux target descriptions.  */

  init_registers_powerpc_32l ();
  init_registers_powerpc_altivec32l ();
  init_registers_powerpc_cell32l ();
  init_registers_powerpc_vsx32l ();
  init_registers_powerpc_isa205_32l ();
  init_registers_powerpc_isa205_altivec32l ();
  init_registers_powerpc_isa205_vsx32l ();
  init_registers_powerpc_e500l ();
  init_registers_powerpc_64l ();
  init_registers_powerpc_altivec64l ();
  init_registers_powerpc_cell64l ();
  init_registers_powerpc_vsx64l ();
  init_registers_powerpc_isa205_64l ();
  init_registers_powerpc_isa205_altivec64l ();
  init_registers_powerpc_isa205_vsx64l ();

  initialize_regsets_info (&ppc_regsets_info);
}
