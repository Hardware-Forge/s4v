# S4V (Security 4 RISC-V)

## Overview

Welcome to **S4V (Security 4 RISC-V)**! 

This repository serves as a collection of various Transient Execution Attacks (TEAs) implementations specifically tailored for RISC-V architectures. The goal is to provide researchers, students, and security engineers with practical examples and templates for understanding and experimenting with these types of vulnerabilities on RISC-V processors.

## Background

Transient Execution Attacks, such as Spectre and Meltdown, exploit the speculative execution features of modern processors to leak sensitive information that should normally be inaccessible. While initially discovered on other architectures, RISC-V, being a modern and increasingly popular ISA, is also susceptible to similar vulnerabilities depending on the specific microarchitecture implementation. This repository explores some of these attacks on RISC-V cores.

## Repository Structure

The repository is organized into two main folders:

1.  **`Template/`**: This folder contains generic "skeleton" implementations for various transient execution attacks. These templates provide the core logic for each attack type and are designed to be adaptable for different RISC-V processor implementations. They serve as a starting point for developing new attack instances or porting existing ones.
2.  **`Processors/`**: This folder contains specific implementations of the attacks targeted at particular RISC-V processor cores. Currently, implementations are provided for:
    * **`BOOM/`**: Attacks specifically implemented and tested against the Berkeley Out-of-Order Machine (BOOM) core.

## Implemented Attacks

This repository includes implementations (or templates) for the following transient execution attacks:

**Templates (`Template/`)**:

* Meltdown
* Spectre V1 (Bounds Check Bypass / Conditional Branch Misprediction)
* Spectre V2 (Branch Target Injection / Indirect Branch Misprediction)
* Spectre V4 (Speculative Store Bypass - SSB)
* Spectre-RSB (Return Stack Buffer)
* RetBleed
* SCSB (Speculative Code Store Bypass)
* Misaligned Meltdown
* Load Value Injection (LVI)
* Inception
* Indirector
* *Under Development:* Crosstalk, SLAM, TikTag, Foreshadow, ZombieLoad, ZenBleed, Ghostrace, Downfall, FPVI.

**Processor-Specific (`Processors/`)**:

* **BOOM**:
    * Meltdown
    * Spectre V1
    * Spectre V2
    * Spectre V4
    * Spectre-RSB
    * RetBleed
    * SCSB
    * Misaligned Meltdown
    * Load Value Injection
    * Inception
    * Indirector

## References and Acknowledgements

Some of the code within the repository has been adapted or inspired by previous work exploring Spectre/Meltdown-like attacks on the RISC-V BOOM microarchitecture. While direct attribution comments might be missing in the source files, the following resources are relevant to the specific attacks mentioned:

* **Spectre V1 & V2 on BOOM:** The repository "BOOM Speculative Attacks" ([boom-attacks](https://github.com/riscv-boom/boom-attacks)) discusses implementations of Spectre V1 (Bounds Check Bypass) and V2 (Branch Target Injection) on BOOM. The implementations in `s4v/Processors/BOOM/Spectrev1/` and `s4v/Processors/BOOM/Spectrev2/` are taken from this work.
* **Misaligned Meltdown on BOOM:** A GitHub issue ([#698](https://github.com/riscv-boom/riscv-boom/issues/698)) describes a Load Address Misaligned Meltdown attack specific to BOOM v3. The code in `s4v/Processors/BOOM/Misaligned-Meltdown/` is based on this work.
* **Spectre-RSB on BOOM:** The work on SonicBOOM defences implementation ([riscv-spectre-mitigations](https://github.com/riscv-spectre-mitigations/Spectre-v2-v5-mitigation-RISCV)) includes a Spectre-RSB attack sources. The code in `s4v/Processors/BOOM/SpectreRSB/` is based on this work.

The initial work inside this repository was made by ([Matteo Coella](https://github.com/Matteo1Colella)) in the context of its Master Thesis at Politecnico di Milano.

## Disclaimer

This repository is intended for educational and research purposes only. The code provided demonstrates security vulnerabilities. Do not use this code for malicious purposes. The authors are not responsible for any misuse of this code.
