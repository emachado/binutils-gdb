/* Target-dependent code for GDB, the GNU debugger.

   Copyright (C) 2000-2017 Free Software Foundation, Inc.

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

#ifndef PPC_TDEP_H
#define PPC_TDEP_H

struct gdbarch;
struct frame_info;
struct value;
struct regcache;
struct type;

/* From ppc-sysv-tdep.c ...  */
enum return_value_convention ppc_sysv_abi_return_value (struct gdbarch *gdbarch,
							struct value *function,
							struct type *valtype,
							struct regcache *regcache,
							gdb_byte *readbuf,
							const gdb_byte *writebuf);
enum return_value_convention ppc_sysv_abi_broken_return_value (struct gdbarch *gdbarch,
							       struct value *function,
							       struct type *valtype,
							       struct regcache *regcache,
							       gdb_byte *readbuf,
							       const gdb_byte *writebuf);
CORE_ADDR ppc_sysv_abi_push_dummy_call (struct gdbarch *gdbarch,
					struct value *function,
					struct regcache *regcache,
					CORE_ADDR bp_addr, int nargs,
					struct value **args, CORE_ADDR sp,
					int struct_return,
					CORE_ADDR struct_addr);
CORE_ADDR ppc64_sysv_abi_push_dummy_call (struct gdbarch *gdbarch,
					  struct value *function,
					  struct regcache *regcache,
					  CORE_ADDR bp_addr, int nargs,
					  struct value **args, CORE_ADDR sp,
					  int struct_return,
					  CORE_ADDR struct_addr);
enum return_value_convention ppc64_sysv_abi_return_value (struct gdbarch *gdbarch,
							  struct value *function,
							  struct type *valtype,
							  struct regcache *regcache,
							  gdb_byte *readbuf,
							  const gdb_byte *writebuf);

/* From rs6000-tdep.c...  */
int altivec_register_p (struct gdbarch *gdbarch, int regno);
int vsx_register_p (struct gdbarch *gdbarch, int regno);
int spe_register_p (struct gdbarch *gdbarch, int regno);

/* Return non-zero if the architecture described by GDBARCH has
   floating-point registers (f0 --- f31 and fpscr).  */
int ppc_floating_point_unit_p (struct gdbarch *gdbarch);

/* Return non-zero if the architecture described by GDBARCH has
   Altivec registers (vr0 --- vr31, vrsave and vscr).  */
int ppc_altivec_support_p (struct gdbarch *gdbarch);

/* Return non-zero if the architecture described by GDBARCH has
   VSX registers (vsr0 --- vsr63).  */
int vsx_support_p (struct gdbarch *gdbarch);
VEC (CORE_ADDR) *ppc_deal_with_atomic_sequence (struct regcache *regcache);


/* Register set description.  */

struct ppc_reg_offsets
{
  /* General-purpose registers.  */
  int r0_offset;
  int gpr_size; /* size for r0-31, pc, ps, lr, ctr.  */
  int xr_size;  /* size for cr, xer, mq.  */
  int pc_offset;
  int ps_offset;
  int cr_offset;
  int lr_offset;
  int ctr_offset;
  int xer_offset;
  int mq_offset;

  /* Floating-point registers.  */
  int f0_offset;
  int fpscr_offset;
  int fpscr_size;

  /* AltiVec registers.  */
  int vr0_offset;
  int vscr_offset;
  int vrsave_offset;
};

extern void ppc_supply_reg (struct regcache *regcache, int regnum,
			    const gdb_byte *regs, size_t offset, int regsize);

extern void ppc_collect_reg (const struct regcache *regcache, int regnum,
			     gdb_byte *regs, size_t offset, int regsize);

/* Supply register REGNUM in the general-purpose register set REGSET
   from the buffer specified by GREGS and LEN to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

extern void ppc_supply_gregset (const struct regset *regset,
				struct regcache *regcache,
				int regnum, const void *gregs, size_t len);

/* Supply register REGNUM in the floating-point register set REGSET
   from the buffer specified by FPREGS and LEN to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

extern void ppc_supply_fpregset (const struct regset *regset,
				 struct regcache *regcache,
				 int regnum, const void *fpregs, size_t len);

/* Supply register REGNUM in the Altivec register set REGSET
   from the buffer specified by VRREGS and LEN to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

extern void ppc_supply_vrregset (const struct regset *regset,
				 struct regcache *regcache,
				 int regnum, const void *vrregs, size_t len);

/* Supply register REGNUM in the VSX register set REGSET
   from the buffer specified by VSXREGS and LEN to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

extern void ppc_supply_vsxregset (const struct regset *regset,
				 struct regcache *regcache,
				 int regnum, const void *vsxregs, size_t len);

/* Collect register REGNUM in the general-purpose register set
   REGSET, from register cache REGCACHE into the buffer specified by
   GREGS and LEN.  If REGNUM is -1, do this for all registers in
   REGSET.  */

extern void ppc_collect_gregset (const struct regset *regset,
				 const struct regcache *regcache,
				 int regnum, void *gregs, size_t len);

/* Collect register REGNUM in the floating-point register set
   REGSET, from register cache REGCACHE into the buffer specified by
   FPREGS and LEN.  If REGNUM is -1, do this for all registers in
   REGSET.  */

extern void ppc_collect_fpregset (const struct regset *regset,
				  const struct regcache *regcache,
				  int regnum, void *fpregs, size_t len);

/* Collect register REGNUM in the Altivec register set
   REGSET from register cache REGCACHE into the buffer specified by
   VRREGS and LEN.  If REGNUM is -1, do this for all registers in
   REGSET.  */

extern void ppc_collect_vrregset (const struct regset *regset,
				  const struct regcache *regcache,
				  int regnum, void *vrregs, size_t len);

/* Collect register REGNUM in the VSX register set
   REGSET from register cache REGCACHE into the buffer specified by
   VSXREGS and LEN.  If REGNUM is -1, do this for all registers in
   REGSET.  */

extern void ppc_collect_vsxregset (const struct regset *regset,
				  const struct regcache *regcache,
				  int regnum, void *vsxregs, size_t len);

/* Private data that this module attaches to struct gdbarch.  */

/* ELF ABI version used by the inferior.  */
enum powerpc_elf_abi
{
  POWERPC_ELF_AUTO,
  POWERPC_ELF_V1,
  POWERPC_ELF_V2,
  POWERPC_ELF_LAST
};

/* Vector ABI used by the inferior.  */
enum powerpc_vector_abi
{
  POWERPC_VEC_AUTO,
  POWERPC_VEC_GENERIC,
  POWERPC_VEC_ALTIVEC,
  POWERPC_VEC_SPE,
  POWERPC_VEC_LAST
};

struct gdbarch_tdep
  {
    int wordsize;		/* Size in bytes of fixed-point word.  */
    int soft_float;		/* Avoid FP registers for arguments?  */

    enum powerpc_elf_abi elf_abi;	/* ELF ABI version.  */

    /* How to pass vector arguments.  Never set to AUTO or LAST.  */
    enum powerpc_vector_abi vector_abi;

    int ppc_gp0_regnum;		/* GPR register 0 */
    int ppc_toc_regnum;		/* TOC register */
    int ppc_ps_regnum;	        /* Processor (or machine) status (%msr) */
    int ppc_cr_regnum;		/* Condition register */
    int ppc_lr_regnum;		/* Link register */
    int ppc_ctr_regnum;		/* Count register */
    int ppc_xer_regnum;		/* Integer exception register */

    /* Not all PPC and RS6000 variants will have the registers
       represented below.  A -1 is used to indicate that the register
       is not present in this variant.  */

    /* Floating-point registers.  */
    int ppc_fp0_regnum;         /* Floating-point register 0.  */
    int ppc_fpscr_regnum;	/* fp status and condition register.  */

    /* Multiplier-Quotient Register (older POWER architectures only).  */
    int ppc_mq_regnum;

    /* POWER7 VSX registers.  */
    int ppc_vsr0_regnum;	/* First VSX register.  */
    int ppc_vsr0_upper_regnum;  /* First right most dword vsx register.  */
    int ppc_efpr0_regnum;	/* First Extended FP register.  */

    /* Altivec registers.  */
    int ppc_vr0_regnum;		/* First AltiVec register.  */
    int ppc_vrsave_regnum;	/* Last AltiVec register.  */

    /* SPE registers.  */
    int ppc_ev0_upper_regnum;   /* First GPR upper half register.  */
    int ppc_ev0_regnum;         /* First ev register.  */
    int ppc_acc_regnum;         /* SPE 'acc' register.  */
    int ppc_spefscr_regnum;     /* SPE 'spefscr' register.  */

    /* Data Stream Control Register.  */
    int ppc_dscr_regnum;
    /* Program Priority Register.  */
    int ppc_ppr_regnum;
    /* Target Address Register.  */
    int ppc_tar_regnum;

    int have_ebb;
    int have_pmu;
    int have_htm;

    /* HTM registers.  */
    int ppc_cr0_regnum;
    int ppc_cfp0_regnum;
    int ppc_cfpscr_regnum;
    int ppc_cvr0_regnum;
    int ppc_cvsr0_regnum;
    int ppc_cvsr0_upper_regnum;
    int ppc_cefpr0_regnum;
    int ppc_cdscr_regnum;
    int ppc_cppr_regnum;
    int ppc_ctar_regnum;

    /* Decimal 128 registers.  */
    int ppc_dl0_regnum;		/* First Decimal128 argument register pair.  */

    /* Offset to ABI specific location where link register is saved.  */
    int lr_frame_offset;	

    /* An array of integers, such that sim_regno[I] is the simulator
       register number for GDB register number I, or -1 if the
       simulator does not implement that register.  */
    int *sim_regno;

    /* ISA-specific types.  */
    struct type *ppc_builtin_type_vec64;
    struct type *ppc_builtin_type_vec128;

    int (*ppc_syscall_record) (struct regcache *regcache);
};


/* Constants for register set sizes.  */
enum
  {
    ppc_num_gprs = 32,		/* 32 general-purpose registers.  */
    ppc_num_fprs = 32,		/* 32 floating-point registers.  */
    ppc_num_srs = 16,		/* 16 segment registers.  */
    ppc_num_vrs = 32,		/* 32 Altivec vector registers.  */
    ppc_num_vshrs = 32,		/* 32 doublewords (dword 1 of vs0~vs31).  */
    ppc_num_vsrs = 64,		/* 64 VSX vector registers.  */
    ppc_num_efprs = 32		/* 32 Extended FP registers.  */
  };


/* Register number constants.  These are GDB internal register
   numbers; they are not used for the simulator or remote targets.
   Extra SPRs (those other than MQ, CTR, LR, XER, SPEFSCR) are given
   numbers above PPC_NUM_REGS.  So are segment registers and other
   target-defined registers.  */
enum {
  PPC_R0_REGNUM = 0,
  PPC_F0_REGNUM = 32,
  PPC_PC_REGNUM = 64,
  PPC_MSR_REGNUM = 65,
  PPC_CR_REGNUM = 66,
  PPC_LR_REGNUM = 67,
  PPC_CTR_REGNUM = 68,
  PPC_XER_REGNUM = 69,
  PPC_FPSCR_REGNUM = 70,
  PPC_MQ_REGNUM = 71,
  PPC_SPE_UPPER_GP0_REGNUM = 72,
  PPC_SPE_ACC_REGNUM = 104,
  PPC_SPE_FSCR_REGNUM = 105,
  PPC_VR0_REGNUM = 106,
  PPC_VSCR_REGNUM = 138,
  PPC_VRSAVE_REGNUM = 139,
  PPC_VSR0_UPPER_REGNUM = 140,
  PPC_VSR31_UPPER_REGNUM = 171,
  PPC_DSCR_REGNUM = 172,
  PPC_PPR_REGNUM = 173,
  PPC_TAR_REGNUM = 174,
  /* EBB registers.  */
  PPC_EBBRR_REGNUM = 175,
  PPC_EBBHR_REGNUM = 176,
  PPC_BESCR_REGNUM = 177,
  /* PMU registers.  */
  PPC_SIAR_REGNUM = 178,
  PPC_SDAR_REGNUM = 179,
  PPC_SIER_REGNUM = 180,
  PPC_MMCR2_REGNUM = 181,
  PPC_MMCR0_REGNUM = 182,
  /* Hardware transactional memory registers.  */
  PPC_TFHAR_REGNUM = 183,
  PPC_TEXASR_REGNUM = 184,
  PPC_TFIAR_REGNUM = 185,

  PPC_CR0_REGNUM,
  PPC_CR1_REGNUM,
  PPC_CR2_REGNUM,
  PPC_CR3_REGNUM,
  PPC_CR4_REGNUM,
  PPC_CR5_REGNUM,
  PPC_CR6_REGNUM,
  PPC_CR7_REGNUM,
  PPC_CR8_REGNUM,
  PPC_CR9_REGNUM,
  PPC_CR10_REGNUM,
  PPC_CR11_REGNUM,
  PPC_CR12_REGNUM,
  PPC_CR13_REGNUM,
  PPC_CR14_REGNUM,
  PPC_CR15_REGNUM,
  PPC_CR16_REGNUM,
  PPC_CR17_REGNUM,
  PPC_CR18_REGNUM,
  PPC_CR19_REGNUM,
  PPC_CR20_REGNUM,
  PPC_CR21_REGNUM,
  PPC_CR22_REGNUM,
  PPC_CR23_REGNUM,
  PPC_CR24_REGNUM,
  PPC_CR25_REGNUM,
  PPC_CR26_REGNUM,
  PPC_CR27_REGNUM,
  PPC_CR28_REGNUM,
  PPC_CR29_REGNUM,
  PPC_CR30_REGNUM,
  PPC_CR31_REGNUM,

  PPC_CF0_REGNUM,
  PPC_CF1_REGNUM,
  PPC_CF2_REGNUM,
  PPC_CF3_REGNUM,
  PPC_CF4_REGNUM,
  PPC_CF5_REGNUM,
  PPC_CF6_REGNUM,
  PPC_CF7_REGNUM,
  PPC_CF8_REGNUM,
  PPC_CF9_REGNUM,
  PPC_CF10_REGNUM,
  PPC_CF11_REGNUM,
  PPC_CF12_REGNUM,
  PPC_CF13_REGNUM,
  PPC_CF14_REGNUM,
  PPC_CF15_REGNUM,
  PPC_CF16_REGNUM,
  PPC_CF17_REGNUM,
  PPC_CF18_REGNUM,
  PPC_CF19_REGNUM,
  PPC_CF20_REGNUM,
  PPC_CF21_REGNUM,
  PPC_CF22_REGNUM,
  PPC_CF23_REGNUM,
  PPC_CF24_REGNUM,
  PPC_CF25_REGNUM,
  PPC_CF26_REGNUM,
  PPC_CF27_REGNUM,
  PPC_CF28_REGNUM,
  PPC_CF29_REGNUM,
  PPC_CF30_REGNUM,
  PPC_CF31_REGNUM,
  PPC_CFPSCR_REGNUM,

  PPC_CVR0_REGNUM,
  PPC_CVR1_REGNUM,
  PPC_CVR2_REGNUM,
  PPC_CVR3_REGNUM,
  PPC_CVR4_REGNUM,
  PPC_CVR5_REGNUM,
  PPC_CVR6_REGNUM,
  PPC_CVR7_REGNUM,
  PPC_CVR8_REGNUM,
  PPC_CVR9_REGNUM,
  PPC_CVR10_REGNUM,
  PPC_CVR11_REGNUM,
  PPC_CVR12_REGNUM,
  PPC_CVR13_REGNUM,
  PPC_CVR14_REGNUM,
  PPC_CVR15_REGNUM,
  PPC_CVR16_REGNUM,
  PPC_CVR17_REGNUM,
  PPC_CVR18_REGNUM,
  PPC_CVR19_REGNUM,
  PPC_CVR20_REGNUM,
  PPC_CVR21_REGNUM,
  PPC_CVR22_REGNUM,
  PPC_CVR23_REGNUM,
  PPC_CVR24_REGNUM,
  PPC_CVR25_REGNUM,
  PPC_CVR26_REGNUM,
  PPC_CVR27_REGNUM,
  PPC_CVR28_REGNUM,
  PPC_CVR29_REGNUM,
  PPC_CVR30_REGNUM,
  PPC_CVR31_REGNUM,
  PPC_CVSCR_REGNUM,
  PPC_CVRSAVE_REGNUM,

  PPC_CVS0H_REGNUM,
  PPC_CVS1H_REGNUM,
  PPC_CVS2H_REGNUM,
  PPC_CVS3H_REGNUM,
  PPC_CVS4H_REGNUM,
  PPC_CVS5H_REGNUM,
  PPC_CVS6H_REGNUM,
  PPC_CVS7H_REGNUM,
  PPC_CVS8H_REGNUM,
  PPC_CVS9H_REGNUM,
  PPC_CVS10H_REGNUM,
  PPC_CVS11H_REGNUM,
  PPC_CVS12H_REGNUM,
  PPC_CVS13H_REGNUM,
  PPC_CVS14H_REGNUM,
  PPC_CVS15H_REGNUM,
  PPC_CVS16H_REGNUM,
  PPC_CVS17H_REGNUM,
  PPC_CVS18H_REGNUM,
  PPC_CVS19H_REGNUM,
  PPC_CVS20H_REGNUM,
  PPC_CVS21H_REGNUM,
  PPC_CVS22H_REGNUM,
  PPC_CVS23H_REGNUM,
  PPC_CVS24H_REGNUM,
  PPC_CVS25H_REGNUM,
  PPC_CVS26H_REGNUM,
  PPC_CVS27H_REGNUM,
  PPC_CVS28H_REGNUM,
  PPC_CVS29H_REGNUM,
  PPC_CVS30H_REGNUM,
  PPC_CVS31H_REGNUM,

  PPC_CDSCR_REGNUM,
  PPC_CPPR_REGNUM,
  PPC_CTAR_REGNUM,
  PPC_NUM_REGS
};

#define PPC_IS_EBBREGSET_REGNUM(i) \
	((i) >= PPC_EBBRR_REGNUM && (i) <= PPC_BESCR_REGNUM)

#define PPC_IS_PMUREGSET_REGNUM(i) \
	((i) >= PPC_SIAR_REGNUM && (i) <= PPC_MMCR0_REGNUM)

#define PPC_IS_TMREGSET_REGNUM(i) \
	((i) >= PPC_TFHAR_REGNUM && (i) <= PPC_TFIAR_REGNUM)

#define PPC_IS_CRREGSET_REGNUM(i) \
	((i) >= PPC_CR0_REGNUM && (i) <= (PPC_CR31_REGNUM))

#define PPC_IS_CFPREGSET_REGNUM(i) \
	((i) >= PPC_CF0_REGNUM && (i) <= (PPC_CFPSCR_REGNUM))

#define PPC_IS_CVMXREGSET_REGNUM(i) \
	((i) >= PPC_CVR0_REGNUM && (i) <= (PPC_CVRSAVE_REGNUM))

#define PPC_IS_CVSXREGSET_REGNUM(i) \
	((i) >= PPC_CVS0H_REGNUM && (i) <= (PPC_CVS31H_REGNUM))

#define PPC_SIZEOF_EBBREGSET	(3*8)
#define PPC_SIZEOF_PMUREGSET	(5*8)
#define PPC_SIZEOF_TM_SPRREGSET	(3*8)
#define PPC32_SIZEOF_CGPRREGSET	(32*4)
#define PPC64_SIZEOF_CGPRREGSET	(32*8)
#define PPC_SIZEOF_CFPRREGSET	(32*8+8)
#define PPC_SIZEOF_CVMXREGSET	(34*16)
#define PPC_SIZEOF_CVSXREGSET	(32*8)

/* An instruction to match.  */

struct ppc_insn_pattern
{
  unsigned int mask;            /* mask the insn with this...  */
  unsigned int data;            /* ...and see if it matches this.  */
  int optional;                 /* If non-zero, this insn may be absent.  */
};

extern int ppc_insns_match_pattern (struct frame_info *frame, CORE_ADDR pc,
				    struct ppc_insn_pattern *pattern,
				    unsigned int *insns);
extern CORE_ADDR ppc_insn_d_field (unsigned int insn);

extern CORE_ADDR ppc_insn_ds_field (unsigned int insn);

extern int ppc_process_record (struct gdbarch *gdbarch,
			       struct regcache *regcache, CORE_ADDR addr);

/* Instruction size.  */
#define PPC_INSN_SIZE 4

/* Estimate for the maximum number of instrctions in a function epilogue.  */
#define PPC_MAX_EPILOGUE_INSTRUCTIONS  52

#endif /* ppc-tdep.h */
