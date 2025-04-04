#include <stdio.h>
#include <stdint.h>
#include <math.h>

double my_pow(double base, int exp) {
    double result = 1.0;

    if (exp < 0) {
        // Gestione degli esponenti negativi
        base = 1.0 / base;
        exp = -exp;
    }

    while (exp) {
        if (exp % 2) {  // Se l'esponente è dispari
            result *= base;
        }
        base *= base;  // Eleva al quadrato la base
        exp /= 2;      // Dividi l'esponente per 2
    }

    return result;
}


void print_float_with_precision(double f, int precision) {
    int sign = (f < 0) ? -1 : 1;
    f = f * sign;  // Rendi il numero positivo per la gestione
    int int_part = (int)f;  // Ottieni la parte intera
    double frac_part = f - int_part;  // Ottieni la parte frazionaria

    // Stampa la parte intera
    printf("Float: %s%d.", (sign == -1 ? "-" : ""), int_part);

    // Calcola la parte frazionaria con precisione
    uint64_t frac_as_int = (uint64_t)(frac_part * my_pow(10, precision));

    // Stampa la parte frazionaria con la precisione desiderata
    printf("%0*llu\n", precision, frac_as_int);
}

int main() {
    // Un valore sottonormale in IEEE 754 (precisione singola)
    float denormal = 1.0e-40f;  // Sottosoglia del numero normale
    float normal = 1.0f;

    // Operazioni per verificare FTZ e DAZ
    float result_ftz = denormal * normal;  // Moltiplicazione
    float result_daz = (denormal + normal) - normal;  // Addizione e sottrazione

    // Output dei risultati
    print_float_with_precision(denormal, 42);
    print_float_with_precision(result_ftz, 42);
    print_float_with_precision(result_daz, 42);

    return 0;
}


