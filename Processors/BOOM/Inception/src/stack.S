.section .text
    .globl frameDump_Inception
# Function intended as a gadget, possibly for speculative execution attacks like "Inception".
# It uses recursion and stack manipulation.
frameDump_Inception:
    # a0 contains the recursion depth, passed as the first argument.
    blez a0, inception_done    # if a0 <= 0 (depth reached), branch to the main gadget logic.
    addi a0, a0, -1            # Decrement the recursion depth counter.
    jal ra, frameDump_Inception  # Recursive call. Saves return address (PC+4) in ra.
                                # The function will eventually return here multiple times.
inception_done:
    # -- Gadget Core Logic --
    # This part manipulates the stack and the return address (ra).

    # Allocate 16 bytes on the stack.
    addi sp, sp, -16
    # Save the current return address (from the caller or the recursive call) onto the stack.
    sd ra, 8(sp)

    # *** Key manipulation: Load return address (ra) from a fixed offset higher up the stack ***
    # This overwrites the legitimate return address with a value presumably placed
    # there by a previous stack frame or attacker-controlled data.
    # This is typical in return stack buffer (RSB) or related exploits.
    ld ra, 72(sp)

    # Deallocate 80 bytes from the stack (net change sp + 64).
    # This cleans up the 16 bytes allocated above and potentially more from prior frames.
    addi sp, sp, 80

    # Perform a calculation on the potentially overwritten 'ra'.
    # The calculation seems unnecessarily complex to achieve a simple result.
    # It might be intended for timing, occupying functional units, or obfuscation.

    # Step 1: ra = ra - 2
    addi ra, ra, -2

    # Step 2: Calculate the value '2' using shifts and floating-point operations.
    addi t1, zero, 2     # t1 = 2
    slli t2, t1, 0x4     # t2 = t1 << 4 = 2 << 4 = 32
    fcvt.s.lu fa4, t1    # fa4 = float(t1) = 2.0
    fcvt.s.lu fa5, t2    # fa5 = float(t2) = 32.0
    fdiv.s fa5, fa5, fa4 # fa5 = fa5 / fa4 = 32.0 / 2.0 = 16.0
    fdiv.s fa5, fa5, fa4 # fa5 = fa5 / fa4 = 16.0 / 2.0 = 8.0
    fdiv.s fa5, fa5, fa4 # fa5 = fa5 / fa4 = 8.0 / 2.0 = 4.0
    fdiv.s fa5, fa5, fa4 # fa5 = fa5 / fa4 = 4.0 / 2.0 = 2.0
    fcvt.lu.s t2, fa5, rtz # t2 = uint64_t(fa5) = uint64_t(2.0) = 2

    # Step 3: ra = ra + 2 (effectively ra = (ra - 2) + 2)
    add ra, ra, t2

    # Return using the manipulated 'ra'.
    # This will likely transfer control to the address loaded from 72(sp),
    # potentially slightly adjusted by the calculation above (which ultimately cancelled out).
    ret