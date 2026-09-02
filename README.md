# crypto-watch

Catálogo de la **kernel crypto API** de Linux en C++23, zero deps.

Lee `/proc/crypto` (exportado por `crypto/proc.c`, `crypto_seq_show`) y muestra
los **algoritmos registrados** en el kernel: hashes, cifradores simétricos
(skcipher/lskcipher/cipher), AEAD, cifrado asimétrico (akcipher),
key-agreement (KPP), RNGs y compresión — con driver, prioridad, refcnt,
tamaños (bloque/IV/digest/clave), módulo e `internal`.

## Features

- **Fuente única**: `/proc/crypto` — 95 algoritmos en este host (registrados vía
  `crypto_register_alg` desde módulos y code built-in)
- **Tipos**: `shash` (43), `skcipher` (13), `rng` (19), `cipher`, `aead`,
  `lskcipher`, `akcipher`, `kpp`, `compression`, `scomp`, `ahash`
- **Clasificación por tipo**: `kind_of()` mapea el string `type` a enum,
  con label descriptivo (`hash (sync)`, `symmetric cipher`, `AEAD`…)
- **Prioridad**: columna `pri` — el kernel elige el driver con mayor prioridad
  para cada nombre (ej. `aes` resuelve a `aesni-intel` prio 300 vs `aes-generic` 100)
- **Detección débil**: `ecb(aes)` de alta prioridad y `geniv=echainiv`
  (CVE-2016-8650) se marcan `!weak`; `~async` y `internal` también se señalan
- **Resumen**: total, internal=n, selftest passed, max priority, recuento por tipo
- **Filtros**: `--type`, `--module`, `--name`, `--internal`, `--no-internal`, `--async`
- **`--top N`**: ordena por prioridad descendente (empates permitidos)
- **Modo watch (`--watch N`)**: refresh periódico del catálogo
- **Salida JSON (`--json`)**: `summary` + array `algorithms` validable
- **Demo mode (`--demo`)**: host sintético AES-NI + SHA-NI + SSSE3 + generic
  (36 registros, 16 shash, 5 skcipher, 3 aead, 4 rng, internal drbg/jitterentropy)
- **`--file`**: parsea un dump (tolera comentarios `#` y filas basura)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 53 checks (clasificación, parser multi-registro, `/proc/crypto`
  real, demo, filtros, --top sort, weak-detection, JSON, --no-color, escapes)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o crypto-watch
```

## Usage

```bash
# Snapshot único (host real)
./crypto-watch

# Solo hashes sincronos
./crypto-watch --type shash

# Solo AES-NI
./crypto-watch --module aesni_intel

# Solo algoritmos internos del kernel (drbg, jitterentropy...)
./crypto-watch --internal

# Solo algoritmos async
./crypto-watch --async

# Top 5 por prioridad
./crypto-watch --top 5

# Modo watch (cada 2s)
./crypto-watch --watch 2

# JSON
./crypto-watch --json

# Demo (host sintético con aceleración AES-NI/SHA-NI)
./crypto-watch --demo

# Parsear un dump con comentarios
./crypto-watch --file sample-crypto.table --no-color

# Sin colores
./crypto-watch --no-color

# Auto-tests
./crypto-watch --selftest
```

## Formato de `/proc/crypto`

Registros separados por línea vacía, campos `key : value`:

```
name         : sha256
driver       : sha256-ssse3
module       : sha256_ssse3
priority     : 250
refcnt       : 2
selftest     : passed
internal     : no
type         : shash
blocksize    : 64
digestsize   : 32

name         : aes
driver       : aesni-intel
...
```

Cada registro corresponde a una llamada `crypto_register_alg()`; el mismo
`name` puede coexistir con varios `driver` (generic + acelerados) y el kernel
resuelve por prioridad. `selftest: passed` indica que el algoritmo pasó su
test de arranque (`crypto_init` → `alg->selftest`).

## Selftest

```bash
./crypto-watch --selftest
# selftest: 53 passed, 0 failed
```