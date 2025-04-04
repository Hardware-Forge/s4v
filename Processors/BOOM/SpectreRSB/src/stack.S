.section .text
.globl frameDump

# Function label
frameDump:
    # Stack manipulation: Adjust stack pointer and save current RA
    addi sp, sp, -16    # Allocate 16 bytes on stack
    sd ra, 8(sp)        # Save current return address (RA) at offset 8

    # *** Key manipulation: Load RA from a fixed offset higher up the stack ***
    # This overwrites the legitimate return address with a value from a previous frame,
    # characteristic of return address manipulation gadgets (like RetBleed, Inception).
    ld ra, 72(sp)       # Load RA from offset 72 relative to current SP

    # Adjust stack pointer (net effect sp + 64 compared to entry)
    addi sp, sp, 80     # Deallocate 80 bytes (includes the 16 allocated earlier)

    # Perform calculation on the loaded RA, seems designed for delay/obfuscation.
    # The net effect of this block is ra = (loaded_ra - 2) + 2 = loaded_ra.
    addi ra, ra, -2     # ra = loaded_ra - 2
    # Sequence to calculate the value 2 using FP instructions:
    addi t1, zero, 2    # t1 = 2
    slli t2, t1, 0x4    # t2 = t1 << 4 = 32
    fcvt.s.lu fa4, t1   # fa4 = float(2.0)
    fcvt.s.lu fa5, t2   # fa5 = float(32.0)
    fdiv.s fa5, fa5, fa4 # fa5 = 32.0 / 2.0 = 16.0
    fdiv.s fa5, fa5, fa4 # fa5 = 16.0 / 2.0 = 8.0
    fdiv.s fa5, fa5, fa4 # fa5 = 8.0 / 2.0 = 4.0
    fdiv.s fa5, fa5, fa4 # fa5 = 4.0 / 2.0 = 2.0
    fcvt.lu.s t2, fa5, rtz # t2 = uint64_t(2.0) = 2
    # Add the calculated value 2 back to ra
    add ra, ra, t2      # ra = (loaded_ra - 2) + 2

    # Return using the manipulated address stored in RA.
    # Control flow likely transfers to the address loaded from 72(sp).
    ret
