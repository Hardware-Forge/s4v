#include "encoding.h"

#if __riscv_xlen == 64
# define LREG ld
# define SREG sd
# define REGBYTES 8
#else
# define LREG lw
# define SREG sw
# define REGBYTES 4
#endif

  .section ".text.init"
  .globl _start
_start:
  // Initialize general-purpose registers
  li  x1, 0
  // ... (rest of registers x2-x31 initialized to 0) ...
  li  x31,0

  // Enable FPU and accelerator if present (sets MSTATUS_FS and MSTATUS_XS)
  li t0, MSTATUS_FS | MSTATUS_XS
  csrs mstatus, t0

  // Sanity check XLEN
  li t0, 1
  slli t0, t0, 31
#if __riscv_xlen == 64
  bgez t0, 1f
#else
  bltz t0, 1f
#endif
2: // XLEN check failed - loop writing to host
  li a0, 1
  la t0, tohost
  SREG a0, 0(t0)
  j 2b
1: // XLEN check passed

// Initialize FPU registers if available
#ifdef __riscv_flen
  la t0, 1f             // Temp trap handler addr
  csrw mtvec, t0        // Set temp trap handler
  fssr x0               // Clear FCSR
  // ... (Initialize f0-f31 to 0) ...
  fmv.s.x f31,x0
1: // End temp FPU init section
#endif

  // --- PMP Configuration ---
  // Configure PMP regions to enforce memory permissions.
  // Assumes M-mode execution and uses TOR (Top of Range) mode.
  // Assumes at least 3 PMP regions are available.
  // Region priorities: Lower index = higher priority.

  // PMP Region 0: Text section (.text, .text.init, etc.) - Read/Execute (RX)
  // Starts implicitly from address 0 (or start of RAM for TOR), ends just before .krodata
  // Note: _stext symbol could be used for start if not 0x80000000. Using _krodata_start as end marker.
  la t0, _krodata_start    // Get end address for Region 0 (start of krodata)
  srli t0, t0, 2           // PMP addresses are word-aligned (shifted right by 2)
  csrw pmpaddr0, t0
  // Config 0: R=1, W=0, X=1, A=1 (TOR), L=0 -> 0b00001101 = 0x0D (RX, TOR)
  li t1, 0x0D

  // PMP Region 1: Kernel Read-Only Data (.krodata) - Read-Only (R)
  // Starts implicitly after Region 0, ends at _krodata_end
  la t0, _krodata_end      // Get end address for Region 1
  srli t0, t0, 2           // Shift right by 2
  csrw pmpaddr1, t0
  // Config 1: R=1, W=0, X=0, A=1 (TOR), L=0 -> 0b00001001 = 0x09 (R, TOR)
  li t2, 0x09
  slli t2, t2, 8           // Shift cfg1 into position (bits 15:8)
  or t1, t1, t2            // Combine cfg1 with cfg0

  // PMP Region 2: RAM (.data, .sdata, .bss, stack, heap) - Read/Write (RW)
  // Starts implicitly after Region 1, covers remaining address space
  // Use -1 for pmpaddr to cover address range up to the maximum possible address with TOR.
  li t0, -1
  csrw pmpaddr2, t0
  // Config 2: R=1, W=1, X=0, A=1 (TOR), L=0 -> 0b00001011 = 0x0B (RW, TOR)
  li t2, 0x0B
  slli t2, t2, 16          // Shift cfg2 into position (bits 23:16)
  or t1, t1, t2            // Combine cfg2 with cfg1 & cfg0

  // Write combined configuration to pmpcfg0 (holds cfgs 0-7 for RV64)
  csrw pmpcfg0, t1

  // Ensure PMP settings apply before executing further code (Instruction Fence)
  fence.i
  // --- End PMP Configuration ---


  // Initialize machine trap vector to the main handler
  la t0, trap_entry
  csrw mtvec, t0

  // Initialize global pointer (gp)
.option push
.option norelax
  la gp, __global_pointer$
.option pop

  // Initialize thread pointer (tp) - base for TLS and initial stack calc
  la  tp, _end + 63
  and tp, tp, -64 // Align tp to 64-byte boundary

  // Get core id (hart ID)
  csrr a0, mhartid
  // Stall secondary cores (simple single-core assumption for now)
  li a1, 1
1:bgeu a0, a1, 1b

  // Set up stack pointer (sp) per core
#define STKSHIFT 17 // Defines 128KB stack space per core
  sll a2, a0, STKSHIFT // stack_offset = hartid * stack_size
  add tp, tp, a2       // Adjust TLS base per core
  add sp, a0, 1        // sp = hartid + 1
  sll sp, sp, STKSHIFT // sp = (hartid + 1) * stack_size
  add sp, sp, tp       // Final sp = top_of_stack_for_hart

  // Jump to C initialization code
  j _init

// --- Trap Handler ---
  .align 2
trap_entry:
  // Save context
  addi sp, sp, -272 // Allocate stack frame
  // ... (Save registers x1, x3-x31) ...
  SREG x31, 31*REGBYTES(sp)

  // Call C handler
  csrr a0, mcause
  csrr a1, mepc
  mv a2, sp
  jal handle_trap
  csrw mepc, a0 // Restore possibly modified mepc

  // Ensure return to M-mode
  li t0, MSTATUS_MPP
  csrs mstatus, t0

  // Restore context
  // ... (Restore registers x1, x3-x31) ...
  LREG x31, 31*REGBYTES(sp)
  addi sp, sp, 272 // Deallocate stack frame
  mret             // Return from trap

// --- TLS Section Definitions ---
// ... (_tdata_begin, _tdata_end, _tbss_end labels) ...

// --- Host Communication Area ---
// ... (tohost, fromhost definitions) ...