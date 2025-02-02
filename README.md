# libhasha

## **libhasha is a standalone lightweight hashing library supporting multiple hashing algorithms written in C**

# Benchmarks

## SHA-2

### SHA-256 Benchmark

<div style="display: flex; gap: 10px;">
   <img src="./assets/sha256.png" alt="SHA-256 Benchmark" width="400">
   <img src="./assets/sha512.png" alt="SHA-512 Benchmark" width="400">
</div>

## SHA-3

### SHA3-256 Benchmark

<div style="display: flex; gap: 10px;">
   <img src="./assets/sha3_256.png" alt="SHA3-256 Benchmark" width="400">
   <img src="./assets/sha3_512.png" alt="SHA3-512 Benchmark" width="400">
</div>

### Supported Algorithms

| **Algorithm** | **Variants**                                  |
|---------------|-----------------------------------------------|
| **CRC**       | `crc32`                                       |
| **MD**        | `md5`                                         |
| **SHA1**      |                                               |
| **SHA2**      | `sha224`, `sha256`, `sha384`, `sha512`,       |
|               | `sha512_224`, `sha512_256`                    |
| **SHA3**      | `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`|
| **Keccak**    | `keccak224`, `keccak256`, `keccak384`,        |
|               | `keccak512`                                   |
| **Blake**     | `blake3`                                      |

# Building
   - ### **Build**
   ```bash
   https://github.com/reslaid32/hasha.git
   cd hasha
   make all
   ```

   - ### **Testing**
   ```bash
   https://github.com/reslaid32/hasha.git
   cd hasha
   sudo make all install check
   ```

## Installing & Uninstalling
   - ### **Installing**
   ```bash
   git clone https://github.com/reslaid32/hasha.git
   cd hasha
   sudo make all install
   ```

   - ### **Removing a library**
   ```bash
   git clone https://github.com/reslaid32/hasha.git
   cd hasha
   sudo make uninstall
   ```
