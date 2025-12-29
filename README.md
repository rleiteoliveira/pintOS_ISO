# PintOS - CIn UFPE

## About
This repository serves as an archive for the projects developed in the **Operating Systems Implementation (IF709)** course, taught by **Prof. Eduardo Tavares** at the **Center for Informatics (CIn) of UFPE**.

The main focus is the educational operating system **PintOS**, where each folder represents an incremental development stage, consolidating fundamental operating system concepts.

## Repository Structure

Unlike branch-based workflows, this repository organizes project evolution into distinct directories. Each folder contains the complete source code (`src`) corresponding to that delivery phase.

### 📁 Original
Contains the **PintOS base code** without modifications. It serves as the starting point and reference for the initial system state before any implementation.

### 📁 Project 2
Focuses on **User Programs** implementation.
- **Argument Passing**: Mechanism to pass command-line arguments to programs.
- **System Calls**: Implementation of system calls to allow user programs to interact securely with the kernel.

### 📁 Project 3
Implementation of **Virtual Memory**.
- **Page Table**: Management of supplemental page tables.
- **Stack Growth**: Support for dynamic stack growth.
- **Swapping**: Mechanism for swapping pages between memory and disk.

### 📁 Project 4
Implementation of the **File System**.
- **Extensible Files**: Support for file growth.
- **Subdirectories**: Ability to create and navigate directory hierarchies.
- **Buffer Cache**: Disk access optimization via cache.

> **Note**: *Project 1 (Threads - Alarm Clock, Priority Scheduling)* was developed, but its features are already integrated and evolved in the subsequent project folders.

## Technologies

- **Language**: C
- **Low Level**: Assembly x86
- **Emulation**: QEMU
- **Environment**: Linux

---
*Academic Disclaimer: This code was developed exclusively for educational purposes within the context of the Operating Systems discipline.*
