# LibFam

[![CI Pipeline](https://github.com/myfamilyorg/libfam/actions/workflows/main.yml/badge.svg)](https://github.com/myfamilyorg/libfam/actions/workflows/main.yml)
[![Release Version](https://img.shields.io/github/v/release/myfamilyorg/libfam.svg?color=blue)](https://github.com/myfamilyorg/libfam/releases)
[![Documentation](https://img.shields.io/static/v1?label=Documentation&message=Github+Pages&color=orange)](https://myfamilyorg.github.io/libfam/)
[![License](https://img.shields.io/github/license/myfamilyorg/libfam.svg)](https://github.com/myfamilyorg/libfam/blob/master/LICENSE)
[![Stars](https://img.shields.io/github/stars/myfamilyorg/libfam.svg?style=social)](https://github.com/myfamilyorg/libfam/stargazers)

<p align="center">
    <img src="docs/MyFamilyLogo.png" alt="Logo">
</p>

# Overview

Libfam is a high-performance, post-quantum-ready, freestanding C library with zero external dependencies.

It provides best-in-class implementations of compression (czip), symmetric cryptography (STORM), hashing (aighthash), CSPRNG, post-quantum KEM/signatures (Kyber/Dilithium with STORM XOF), safe formatting, and a modern test framework — all with 100% test coverage and direct kernel interfaces (io_uring + minimal syscalls).

Designed for systems programming, embedded, servers, and security-critical applications where speed, simplicity, and auditability matter.

# Building Libfam

Instructions assume ubuntu minimal, but similar commands are possible with other distros. Basically you need to have a c compiler (clang suggested, but gcc supported) and 'sh'. Supported platforms: x86_64 and aarch64 Linux.

```
sudo apt update
sudo apt install clang -y
wget https://github.com/myfamilyorg/libfam/archive/refs/tags/2.0.0.tar.gz
gzip -dc 2.0.0.tar.gz | tar xvf -
cd libfam-2.0.0
./build
sudo ./build install
```

# Example usage

```
    // test.c
    #include <libfam/format.h>
    #include <libfam/main.h>

    i32 main(i32 argc, u8 **argv, u8 **envp) {
        println("Hello from libfam — {} + {} = {}", 1, 1, 2);
        return 0;
    }
```

```
clang -ffreestanding -nostdlib test.c -lfam
```

Test can be run with the following command:
```
./build test
```

Coverage can be calculated with the following command:
```
sudo apt install gcc -y
./build cov
```

Benches can be run with the following command:
```
./build bench
```

# Features
* [Storm](docs/storm.md) - A symmetric encryption function.
* [BiblePOW](docs/biblepow.md) - A Bible-based proof of work function.
* [Czip](docs/compression.md) - A compression tool.
* [Formatting](docs/formatting.md) - Formatting.

> “Just as a body, though one, has many parts, but all its many parts form one body, so it is with Christ. For we were all baptized by one Spirit so as to form one body—whether Jews or Gentiles, slave or free—and we were all given the one Spirit to drink. Even so the body is not made up of one part but of many.”
> — **1 Corinthians 12:12-14**


