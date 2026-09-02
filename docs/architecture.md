# Arquitectura — crypto-watch

## Flujo

```
/proc/crypto  ──►  load_catalog()  ──►  Catalog{ts, algos[N]}
                                            │
                ┌───────────────────────────┼───────────────────────────┐
                ▼                           ▼                           ▼
         render_catalog()            render_json()                 (watch loop)
         (tabla drivers)             (summary + algorithms)        re-read N s
```

## Estructura de datos

- `Algo` — un registro: `name`, `driver`, `module`, `type`, `priority`,
  `refcnt`, `selftest`, `internal`, `blocksize`, `digestsize`, `ivsize`,
  `maxauthsize`, `maxkeysize`, `minkeysize`, `chunksize`, `walksize`, `async`,
  `seedsize`, `statesize`, `geniv`. Los campos ausentes quedan a 0/vacío.
- `Kind` — enum derivado del string `type` vía `kind_of()` (unknown si no casa).
- `Catalog` — vector de algoritmos + agregados (`kind_count`, `internal_count`,
  `highest_priority`) para el resumen del header.
- `Filters { type, module, name, internal, no_internal, async, top }` —
  criterios evaluados por `passes()`. `--top N` ordena por **prioridad**
  descendente después del filtro.

## Parsing

- Registros separados por **línea vacía** (a diferencia de /proc/net/snmp6,
  que usa un contador por línea).
- Campos `key : value` (colon+espacio); el parser recorta whitespace en key y
  valor, tolera comentarios `#`, filas malformadas y CR de Windows.
- Hasta que aparece la primera línea vacía, el registro no se hace visible
  (`flush()` al separador). Un `/proc/crypto` real sin trailing blank line
  también se cierra bien: flush final tras EOF.
- `--file` con dumps comentados es el mismo parser — el selftest lo cubre con
  un dump de 3 registros mezclado con comentarios (patrón del README).

## Renderizado

- Columnas: driver (bold), type, pri, ref, bs (blocksize), iv, dg (digest),
  key (maxkeysize, o seedsize para RNG, o maxauthsize para AEAD) + module dim.
- Color por prioridad: ≥250 amarillo, internal magenta, refcnt=0 dim, resto verde.
- Flags: `!weak` rojo (ecb(aes) high-prio o geniv=echainiv), `~async` cyan,
  ` internal` magenta.
- `geniv` se muestra como `[seqiv]` cuando el driver lo declara.
- Paleta ANSI **mutable** — `--no-color` la vacía de verdad.

## Decisiones

- **C++23 stdlib-only**: g++ directo, cero dependencias.
- **Catálogo vs contadores**: mientras snmp-watch/snmp6-watch muestran
  contadores acumulados, /proc/crypto es un registro estático de algoritmos
  registrados — por eso el modo watch es de refresco (no hay deltas útiles) y
  el interés está en la clasificación/filtrado/prioridad.
- **`--demo`**: host sintético con AES-NI + SHA-NI + SSSE3 + generic para
  mostrar aceleración x86 (prio 250-400), internal (drbg, jitterentropy),
  weak-flag (ecb(aes) aesni), async y tipos poco comunes (kpp ecdh/curve25519,
  compression deflate, scomp lz4).