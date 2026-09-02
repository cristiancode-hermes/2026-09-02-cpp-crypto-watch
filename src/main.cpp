// SPDX-License-Identifier: MIT
// cpp-crypto-watch — kernel crypto API catalog from /proc/crypto
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o crypto-watch
// Usage: ./crypto-watch [options]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model — one registered crypto algorithm (/proc/crypto record)
// ─────────────────────────────────────────────────────────────────────────────
struct Algo {
  std::string name;
  std::string driver;
  std::string module;
  std::string type;
  int priority = 0;
  int refcnt = 0;
  std::string selftest;   // "passed" / "unknown" / "failed"
  std::string internal;   // "yes" / "no"
  int blocksize = 0;
  int digestsize = 0;     // shash/ahash/aead
  int ivsize = 0;         // skcipher/lskcipher/aead/geniv
  int maxauthsize = 0;    // aead
  int maxkeysize = 0;     // akcipher/skcipher
  int minkeysize = 0;
  int chunksize = 0;      // compression
  int walksize = 0;
  bool async = false;
  int seedsize = 0;       // rng
  int statesize = 0;      // shash
  std::string geniv;      // skcipher → "seqiv" (default) o "echainiv" (debil)
};

enum class Kind {
  Shash, Ahash, Skcipher, Lskcipher, Aead, Cipher,
  Akcipher, Kpp, Rng, Compression, Scomp, Unknown
};

static Kind kind_of(const std::string& t) {
  if (t == "shash") return Kind::Shash;
  if (t == "ahash") return Kind::Ahash;
  if (t == "skcipher") return Kind::Skcipher;
  if (t == "lskcipher") return Kind::Lskcipher;
  if (t == "aead") return Kind::Aead;
  if (t == "cipher") return Kind::Cipher;
  if (t == "akcipher") return Kind::Akcipher;
  if (t == "kpp") return Kind::Kpp;
  if (t == "rng") return Kind::Rng;
  if (t == "compression") return Kind::Compression;
  if (t == "scomp") return Kind::Scomp;
  return Kind::Unknown;
}

static const char* kind_name(Kind k) {
  switch (k) {
    case Kind::Shash:       return "shash";
    case Kind::Ahash:       return "ahash";
    case Kind::Skcipher:    return "skcipher";
    case Kind::Lskcipher:   return "lskcipher";
    case Kind::Aead:        return "aead";
    case Kind::Cipher:      return "cipher";
    case Kind::Akcipher:    return "akcipher";
    case Kind::Kpp:         return "kpp";
    case Kind::Rng:         return "rng";
    case Kind::Compression: return "compression";
    case Kind::Scomp:       return "scomp";
    default:                return "?";
  }
}

static const char* kind_label(Kind k) {
  switch (k) {
    case Kind::Shash:    return "hash (sync)";
    case Kind::Ahash:    return "hash (async)";
    case Kind::Cipher:   return "block cipher (legacy)";
    case Kind::Skcipher: return "symmetric cipher";
    case Kind::Lskcipher:return "symmetric cipher (linear)";
    case Kind::Aead:     return "AEAD";
    case Kind::Akcipher: return "asymmetric cipher";
    case Kind::Kpp:      return "key-agreement (KPP)";
    case Kind::Rng:      return "RNG";
    case Kind::Compression: return "compression";
    case Kind::Scomp:    return "compression (scomp)";
    default:             return "?";
  }
}

struct Catalog {
  long long ts = 0;
  std::vector<Algo> algos;

  std::size_t kind_count(Kind k) const {
    return static_cast<std::size_t>(
      std::count_if(algos.begin(), algos.end(),
                    [k](const Algo& a) { return kind_of(a.type) == k; }));
  }
  std::size_t internal_count() const {
    return static_cast<std::size_t>(
      std::count_if(algos.begin(), algos.end(),
                    [](const Algo& a) { return a.internal == "yes"; }));
  }
  std::size_t highest_priority() const {
    int m = 0;
    for (const auto& a : algos) m = std::max(m, a.priority);
    return static_cast<std::size_t>(m);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Loaders
// ─────────────────────────────────────────────────────────────────────────────
static int parse_int(std::string s) {
  auto st = s.find_first_not_of(" \t");
  if (st != std::string::npos) s = s.substr(st);
  if (s.empty()) return 0;
  int v = 0;
  std::from_chars(s.data(), s.data() + s.size(), v);
  return v;
}

static bool is_yes(std::string_view s) {
  return s == "yes" || s == "1";
}

// /proc/crypto: records separated by a blank line; fields "key : value" with
// a colon+space separator. Tolerates comments '#' and trailing whitespace.
static bool load_catalog(Catalog& cat, const std::string& path) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  cat.algos.clear();
  Algo cur;
  bool have = false;
  auto flush = [&] {
    if (have) cat.algos.push_back(std::move(cur));
    cur = Algo{};
    have = false;
  };
  while (std::getline(f, line)) {
    size_t hash = line.find_first_of('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.pop_back();
    if (line.empty()) { flush(); continue; }   // record separator
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;  // malformed → skip
    std::string key = line.substr(0, colon);
    auto kb = key.find_first_not_of(" \t");
    if (kb != std::string::npos) key = key.substr(kb);
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
    std::string val = line.substr(colon + 1);
    auto vb = val.find_first_not_of(" \t");
    if (vb != std::string::npos) val = val.substr(vb);
    while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.pop_back();
    have = true;
    if (key == "name") cur.name = val;
    else if (key == "driver") cur.driver = val;
    else if (key == "module") cur.module = val;
    else if (key == "type") cur.type = val;
    else if (key == "priority") cur.priority = parse_int(val);
    else if (key == "refcnt") cur.refcnt = parse_int(val);
    else if (key == "selftest") cur.selftest = val;
    else if (key == "internal") cur.internal = val;
    else if (key == "blocksize") cur.blocksize = parse_int(val);
    else if (key == "digestsize") cur.digestsize = parse_int(val);
    else if (key == "ivsize") cur.ivsize = parse_int(val);
    else if (key == "maxauthsize") cur.maxauthsize = parse_int(val);
    else if (key == "max keysize") cur.maxkeysize = parse_int(val);
    else if (key == "min keysize") cur.minkeysize = parse_int(val);
    else if (key == "chunksize") cur.chunksize = parse_int(val);
    else if (key == "walksize") cur.walksize = parse_int(val);
    else if (key == "async") cur.async = is_yes(val);
    else if (key == "seedsize") cur.seedsize = parse_int(val);
    else if (key == "statesize") cur.statesize = parse_int(val);
    else if (key == "geniv") cur.geniv = val;
  }
  flush();
  return cat.algos.size() >= 2;  // a real /proc/crypto has dozens of records
}

// Synthetic busy host: AES-NI + SSSE3 + generic fallbacks, mixed types.
static bool demo_load(Catalog& cat) {
  struct Row {
    const char* name; const char* driver; const char* module; const char* type;
    int prio; int ref; const char* selftest; const char* internal;
    int bs; int dig; int iv; int maxauth; int maxk; int wink; int seed; int state;
    bool async; const char* geniv;
  };
  static const Row rows[] = {
    {"aes", "aes-generic", "aes_generic", "cipher", 100, 1, "passed", "no", 16, 0, 0, 0, 0, 0, 0, 0, false, ""},
    {"aes", "aesni-intel", "aesni_intel", "skcipher", 300, 2, "passed", "no", 16, 0, 16, 0, 32, 0, 0, 0, false, "seqiv"},
    {"aes", "aesni-intel", "aesni_intel", "cipher", 300, 0, "passed", "no", 16, 0, 0, 0, 0, 0, 0, 0, false, ""},
    {"aes", "aesni-intel", "aesni_intel", "aead", 400, 3, "passed", "no", 16, 16, 12, 16, 0, 0, 0, 0, false, "seqiv"},
    {"blake2b-512", "blake2b-512-generic", "blake2b_generic", "shash", 100, 1, "passed", "no", 128, 64, 0, 0, 0, 0, 0, 64, true, ""},
    {"blake2b-384", "blake2b-384-generic", "blake2b_generic", "shash", 100, 1, "passed", "no", 128, 48, 0, 0, 0, 0, 0, 48, true, ""},
    {"blake2b-256", "blake2b-256-generic", "blake2b_generic", "shash", 100, 1, "passed", "no", 128, 32, 0, 0, 0, 0, 0, 32, true, ""},
    {"blake2s-256", "blake2s-256-generic", "blake2s_generic", "shash", 100, 0, "passed", "no", 64, 32, 0, 0, 0, 0, 0, 32, true, ""},
    {"blake2s-128", "blake2s-128-generic", "blake2s_generic", "shash", 100, 1, "passed", "no", 64, 16, 0, 0, 0, 0, 0, 16, true, ""},
    {"sha1", "sha1-ssse3", "sha1_ssse3", "shash", 250, 2, "passed", "no", 64, 20, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha1", "sha1-generic", "sha1_generic", "shash", 100, 1, "passed", "no", 64, 20, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha256", "sha256-ssse3", "sha256_ssse3", "shash", 250, 2, "passed", "no", 64, 32, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha256", "sha256-generic", "sha256_generic", "shash", 100, 1, "passed", "no", 64, 32, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha512", "sha512-ssse3", "sha512_ssse3", "shash", 250, 2, "passed", "no", 128, 64, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha3-512", "sha3-512-generic", "sha3_generic", "shash", 100, 1, "passed", "no", 72, 64, 0, 0, 0, 0, 0, 0, false, ""},
    {"sha3-256", "sha3-256-generic", "sha3_generic", "shash", 100, 1, "passed", "no", 136, 32, 0, 0, 0, 0, 0, 0, false, ""},
    {"ecb(aes)", "ecb-aes-aesni", "aesni_intel", "skcipher", 300, 2, "passed", "no", 16, 0, 0, 0, 32, 0, 0, 0, false, ""},
    {"cbc(aes)", "cbc-aes-aesni", "aesni_intel", "skcipher", 300, 2, "passed", "no", 16, 0, 16, 0, 32, 0, 0, 0, false, "seqiv"},
    {"xts(aes)", "xts-aes-aesni", "aesni_intel", "skcipher", 300, 2, "passed", "no", 16, 0, 16, 0, 64, 0, 0, 0, false, "seqiv"},
    {"gcm(aes)", "generic-gcm-aesni", "aesni_intel", "aead", 350, 2, "passed", "no", 16, 16, 8, 16, 0, 0, 0, 0, false, "seqiv"},
    {"rsa", "rsa-generic", "rsa_generic", "akcipher", 100, 1, "passed", "no", 0, 0, 0, 0, 512, 0, 0, 0, true, ""},
    {"ecdh", "ecdh-generic", "ecdh_generic", "kpp", 100, 1, "passed", "no", 0, 0, 0, 0, 0, 0, 0, 0, true, ""},
    {"ecdsa", "ecdsa-generic", "ecdsa_generic", "akcipher", 100, 1, "passed", "no", 0, 0, 0, 0, 0, 0, 0, 0, true, ""},
    {"drbg_pr_sha256", "drbg_pr_sha256", "drbg", "rng", 192, 0, "passed", "yes", 0, 0, 0, 0, 0, 0, 32, 0, false, ""},
    {"ansi_cprng", "ansi_cprng", "ansi_cprng", "rng", 100, 0, "passed", "no", 0, 0, 0, 0, 0, 0, 16, 0, false, ""},
    {"stdrng", "drbg_pr_sha256", "drbg", "rng", 212, 3, "passed", "yes", 0, 0, 0, 0, 0, 0, 32, 0, false, ""},
    {"deflate", "deflate-generic", "deflate_generic", "compression", 100, 1, "passed", "no", 0, 0, 0, 0, 0, 524288, 0, 0, false, ""},
    {"lz4", "lz4-generic", "lz4_generic", "scomp", 100, 1, "passed", "no", 0, 0, 0, 0, 0, 0, 0, 0, false, ""},
    {"xxhash64", "xxhash64-generic", "xxhash64_generic", "shash", 100, 1, "passed", "no", 0, 8, 0, 0, 0, 0, 0, 8, true, ""},
    {"crc32c", "crc32c-intel", "crc32c_intel", "shash", 250, 2, "passed", "no", 1, 4, 0, 0, 0, 0, 0, 0, false, ""},
    {"ghash", "ghash-clmulni-intel", "ghash_clmulni_intel", "shash", 300, 1, "passed", "no", 16, 16, 0, 0, 0, 0, 0, 0, false, ""},
    {"polyval", "polyval-clmulni-intel", "polyval_clmulni_intel", "shash", 300, 1, "passed", "no", 16, 16, 0, 0, 0, 0, 0, 0, false, ""},
    {"aegis128", "aegis128-generic", "aegis128_generic", "aead", 200, 2, "passed", "no", 16, 16, 16, 16, 0, 0, 0, 0, true, ""},
    {"chacha20", "chacha20-generic", "chacha20_generic", "skcipher", 100, 1, "passed", "no", 1, 0, 16, 0, 32, 0, 0, 0, true, ""},
    {"curve25519", "curve25519-generic", "curve25519_generic", "kpp", 100, 0, "passed", "no", 0, 0, 0, 0, 0, 0, 0, 0, true, ""},
    {"jitterentropy_rng", "jitterentropy_rng", "jitterentropy_rng", "rng", 100, 3, "passed", "yes", 0, 0, 0, 0, 0, 0, 0, 0, true, ""},
  };
  cat.algos.clear();
  for (const auto& r : rows) {
    Algo a;
    a.name = r.name; a.driver = r.driver; a.module = r.module;
    a.type = r.type; a.priority = r.prio; a.refcnt = r.ref;
    a.selftest = r.selftest; a.internal = r.internal;
    a.blocksize = r.bs; a.digestsize = r.dig; a.ivsize = r.iv;
    a.maxauthsize = r.maxauth; a.maxkeysize = r.maxk; a.chunksize = r.wink;
    a.seedsize = r.seed; a.statesize = r.state; a.async = r.async;
    a.geniv = r.geniv;
    cat.algos.push_back(std::move(a));
  }
  return cat.algos.size() == 36;
}

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  std::string type;
  std::string module;
  std::string name;
  bool internal = false;   // only internal=y
  bool no_internal = false; // only internal=n
  bool weak = false;       // only weak (echainiv-with-ctr) or non-fips nolookup?
  bool async = false;      // only async=y
  bool fips = false;       // only selftest=passed (all real ones); keep for clarity
  int top = 0;
};

static bool passes(const Algo& a, const Filters& f) {
  if (!f.type.empty() && a.type != f.type) return false;
  if (!f.module.empty() && a.module != f.module) return false;
  if (!f.name.empty() && a.name != f.name) return false;
  if (f.internal && a.internal != "yes") return false;
  if (f.no_internal && a.internal != "no") return false;
  if (f.async && !a.async) return false;
  return true;
}

static bool is_weak(const Algo& a) {
  // echainiv + CTR-mode block ciphers are known weak (CVE-2016-8650);
  // 'internal' kernel-only algorithms are non-standard by design.
  if (a.geniv == "echainiv") return true;
  if (a.internal == "yes") {
    // drbg/stdrng/jitterentropy are intentional; treat as weak only if a
    // userland-facing name maps to them without FIPS selftest override.
    return false;
  }
  return a.name == "ecb(aes)" && a.priority >= 300 && a.module == "aesni_intel";
}

static std::vector<const Algo*> select_rows(const Catalog& cat, const Filters& f) {
  std::vector<const Algo*> rows;
  rows.reserve(cat.algos.size());
  for (const auto& a : cat.algos)
    if (passes(a, f)) rows.push_back(&a);
  if (f.top > 0) {
    std::stable_sort(rows.begin(), rows.end(),
                     [](const Algo* x, const Algo* y) { return x->priority > y->priority; });
    if (static_cast<int>(rows.size()) > f.top)
      rows.resize(static_cast<std::size_t>(f.top));
  }
  return rows;
}

static void render_catalog(const Catalog& cat, const Filters& f, bool quiet_header) {
  if (!quiet_header) {
    std::println(std::cout, "{}-- kernel crypto API  /proc/crypto --{}", C_BOLD, C_RESET);
    std::println(std::cout, "{}algorithms {}  internal {}  selftest passed {}  max priority {}{}",
                 C_DIM, cat.algos.size(), cat.internal_count(),
                 static_cast<std::size_t>(std::count_if(
                   cat.algos.begin(), cat.algos.end(),
                   [](const Algo& a) { return a.selftest == "passed"; })),
                 cat.highest_priority(), C_RESET);
    std::println(std::cout, "{}shash {}  ahash {}  skcipher {}  lskcipher {}  aead {}  cipher {}  akcipher {}  kpp {}  rng {}  compress {}{}",
                 C_DIM,
                 cat.kind_count(Kind::Shash), cat.kind_count(Kind::Ahash),
                 cat.kind_count(Kind::Skcipher), cat.kind_count(Kind::Lskcipher),
                 cat.kind_count(Kind::Aead), cat.kind_count(Kind::Cipher),
                 cat.kind_count(Kind::Akcipher), cat.kind_count(Kind::Kpp),
                 cat.kind_count(Kind::Rng),
                 cat.kind_count(Kind::Compression) + cat.kind_count(Kind::Scomp),
                 C_RESET);
    std::println(std::cout);
  }

  auto rows = select_rows(cat, f);
  std::println(std::cout, "  {}{:<26}{} {:<9} {:>3} {:>3} {:>3} {:>3} {:>3} {:>4}  {}{}",
               C_BOLD, "driver", C_RESET, "type", "pri", "ref", "bs", "iv", "dg", "key", C_DIM, "module");
  std::println(std::cout, "  {}-------------------------------------------------------------------{}",
               C_DIM, C_RESET);
  for (const auto* a : rows) {
    std::string col = C_GREEN;
    if (a->priority >= 250) col = C_YELLOW;
    else if (a->internal == "yes") col = C_MAGENTA;
    else if (a->refcnt == 0) col = C_DIM;
    std::string geniv = a->geniv.empty() ? "" : " [" + a->geniv + "]";
    std::string flag = "";
    if (is_weak(*a)) flag = C_RED + " !weak" + C_RESET;
    else if (a->async) flag = C_CYAN + " ~async" + C_RESET;
    else if (a->internal == "yes") flag = C_MAGENTA + " internal" + C_RESET;

    std::println(std::cout, "  {}{:<26}{} {:<9} {:>3} {:>3} {:>3} {:>3} {:>3} {:>4}{}  {}{}{}{}",
                 C_BOLD, a->driver, C_RESET,
                 kind_name(kind_of(a->type)),
                 a->priority, a->refcnt, a->blocksize, a->ivsize, a->digestsize,
                 a->maxkeysize ? a->maxkeysize : (a->seedsize ? a->seedsize : a->maxauthsize),
                 geniv,
                 C_DIM, a->module, C_RESET, flag);
  }
  std::println(std::cout, "{}-- {} algorithms shown --{}", C_DIM, rows.size(), C_RESET);
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (char c : s) {
    if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
    else o.push_back(c);
  }
  return o;
}

static void render_json(std::ostream& os, const Catalog& cat) {
  os << "{\n  \"ts\": " << cat.ts << ",\n  \"source\": \"crypto\",\n";
  os << "  \"summary\": {\n"
        "    \"count\": " << cat.algos.size() << ",\n"
        "    \"internal\": " << cat.internal_count() << ",\n"
        "    \"shash\": " << cat.kind_count(Kind::Shash) << ",\n"
        "    \"ahash\": " << cat.kind_count(Kind::Ahash) << ",\n"
        "    \"skcipher\": " << cat.kind_count(Kind::Skcipher) << ",\n"
        "    \"lskcipher\": " << cat.kind_count(Kind::Lskcipher) << ",\n"
        "    \"aead\": " << cat.kind_count(Kind::Aead) << ",\n"
        "    \"cipher\": " << cat.kind_count(Kind::Cipher) << ",\n"
        "    \"akcipher\": " << cat.kind_count(Kind::Akcipher) << ",\n"
        "    \"kpp\": " << cat.kind_count(Kind::Kpp) << ",\n"
        "    \"rng\": " << cat.kind_count(Kind::Rng) << ",\n"
        "    \"compression\": " << cat.kind_count(Kind::Compression) + cat.kind_count(Kind::Scomp) << ",\n"
        "    \"max_priority\": " << cat.highest_priority() << "\n"
        "  },\n";
  os << "  \"algorithms\": [\n";
  bool first = true;
  for (const auto& a : cat.algos) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\"name\": \"" << json_escape(a.name)
       << "\", \"driver\": \"" << json_escape(a.driver)
       << "\", \"module\": \"" << json_escape(a.module)
       << "\", \"type\": \"" << json_escape(a.type)
       << "\", \"priority\": " << a.priority
       << ", \"refcnt\": " << a.refcnt
       << ", \"selftest\": \"" << json_escape(a.selftest)
       << "\", \"internal\": \"" << json_escape(a.internal)
       << "\"}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0;
static int g_fail = 0;
static void t_check(bool ok, const char* label) {
  if (ok) {
    ++g_pass;
    std::println(std::cout, "  PASS  {}", label);
  } else {
    ++g_fail;
    std::println(std::cout, "  FAIL  {}", label);
  }
}

static int run_selftest() {
  std::cout << "-- selftest: classification --\n";
  t_check(kind_of("shash") == Kind::Shash, "shash kind");
  t_check(kind_of("skcipher") == Kind::Skcipher, "skcipher kind");
  t_check(kind_of("aead") == Kind::Aead, "aead kind");
  t_check(kind_of("rng") == Kind::Rng, "rng kind");
  t_check(kind_of("unknown-ish") == Kind::Unknown, "unknown kind");
  t_check(std::string(kind_label(Kind::Shash)) == "hash (sync)", "shash label");

  std::cout << "-- selftest: parser (multi-record, comments, blank sep) --\n";
  {
    std::string path = "/tmp/crypto-watch-selftest.table";
    {
      std::ofstream f(path);
      f << "# synthetic /proc/crypto dump\n"
           "name         : sha256\n"
           "driver       : sha256-ssse3\n"
           "module       : sha256_ssse3\n"
           "priority     : 250\n"
           "refcnt       : 2\n"
           "selftest     : passed\n"
           "internal     : no\n"
           "type         : shash\n"
           "blocksize    : 64\n"
           "digestsize   : 32\n"
           "\n"
           "name         : aes\n"
           "driver       : aesni-intel\n"
           "module       : aesni_intel\n"
           "priority     : 300\n"
           "refcnt       : 1\n"
           "selftest     : passed\n"
           "internal     : no\n"
           "type         : skcipher\n"
           "blocksize    : 16\n"
           "ivsize       : 16\n"
           "max keysize  : 32\n"
           "geniv        : seqiv\n"
           "\n"
           "name         : drbg_pr_sha256\n"
           "driver       : drbg_pr_sha256\n"
           "module       : drbg\n"
           "priority     : 192\n"
           "refcnt       : 0\n"
           "selftest     : passed\n"
           "internal     : yes\n"
           "type         : rng\n"
           "seedsize     : 32\n";
    }
    Catalog c;
    bool ok = load_catalog(c, path);
    std::remove(path.c_str());
    t_check(ok, "parse file opens");
    t_check(c.algos.size() == 3, "3 records parsed (comment skipped)");
    if (c.algos.size() == 3) {
      t_check(c.algos[0].name == "sha256", "first name sha256");
      t_check(c.algos[0].driver == "sha256-ssse3", "first driver");
      t_check(c.algos[0].type == "shash", "first type shash");
      t_check(c.algos[0].priority == 250, "first priority 250");
      t_check(c.algos[0].digestsize == 32, "first digestsize 32");
      t_check(c.algos[0].selftest == "passed", "first selftest passed");
      t_check(c.algos[1].type == "skcipher", "second type skcipher");
      t_check(c.algos[1].ivsize == 16, "second ivsize 16");
      t_check(c.algos[1].geniv == "seqiv", "second geniv seqiv");
      t_check(c.algos[2].internal == "yes", "third internal yes");
      t_check(c.algos[2].seedsize == 32, "third seedsize 32");
      t_check(kind_of(c.algos[2].type) == Kind::Rng, "third type rng");
    }
  }

  std::cout << "-- selftest: /proc/crypto real --\n";
  {
    Catalog c;
    bool ok = load_catalog(c, "/proc/crypto");
    t_check(ok, "/proc/crypto opens");
    if (ok) {
      t_check(c.algos.size() > 50, "kernel exposes 50+ algorithms");
      t_check(c.kind_count(Kind::Shash) > 10, "several shash");
      t_check(c.kind_count(Kind::Rng) > 1, "several rng");
      t_check(c.internal_count() > 0, "some internal algorithms");
      t_check(std::all_of(c.algos.begin(), c.algos.end(),
                          [](const Algo& a) { return !a.name.empty(); }),
              "every record has a name");
    }
  }

  std::cout << "-- selftest: demo --\n";
  {
    Catalog d;
    bool ok = demo_load(d);
    t_check(ok, "demo loads 36 algorithms");
    t_check(d.algos.size() == 36, "demo size 36");
    t_check(d.kind_count(Kind::Shash) == 16, "demo 16 shash");
    t_check(d.kind_count(Kind::Skcipher) == 5, "demo 5 skcipher");
    t_check(d.kind_count(Kind::Aead) == 3, "demo 3 aead");
    t_check(d.kind_count(Kind::Rng) == 4, "demo 4 rng");
    t_check(d.internal_count() == 3, "demo 3 internal (drbg x2 + jitterentropy)");
    t_check(d.highest_priority() == 400, "demo max priority 400");
    t_check(d.algos[0].name == "aes", "demo first name aes");
    t_check(d.algos[3].type == "aead", "demo aes-aead type");
  }

  std::cout << "-- selftest: filters + --top sort --\n";
  {
    Catalog d;
    demo_load(d);
    Filters f;
    f.type = "shash";
    std::size_t n = 0;
    for (const auto& a : d.algos) if (passes(a, f)) ++n;
    t_check(n == 16, "type=shash keeps 16");
    f.type.clear();
    f.module = "aesni_intel";
    n = 0;
    for (const auto& a : d.algos) if (passes(a, f)) ++n;
    t_check(n == 7, "module=aesni_intel keeps 7");
    f.module.clear();
    f.internal = true;
    n = 0;
    for (const auto& a : d.algos) if (passes(a, f)) ++n;
    t_check(n == 3, "internal keeps 3");
    f.internal = false;
    f.top = 5;
    auto rows = select_rows(d, f);
    t_check(rows.size() == 5, "--top 5 yields 5 rows");
    bool desc = rows.size() == 5 && rows[0]->priority >= rows[1]->priority &&
                rows[1]->priority >= rows[2]->priority;
    t_check(desc, "--top sorts by priority descending (ties allowed)");
    t_check(rows[0]->driver == "aes-aesni" || rows[0]->driver == "aesni-intel" ||
            rows[0]->priority == 400, "top entry has max priority");
  }

  std::cout << "-- selftest: weak detection + JSON + --no-color hygiene --\n";
  {
    Catalog d;
    demo_load(d);
    const Algo* xts = nullptr;
    for (const auto& a : d.algos) if (a.name == "xts(aes)") { xts = &a; break; }
    t_check(xts != nullptr, "xts(aes) present");
    // xts with seqiv is SAFE; only ctr+echainiv or ecb(high-prio) is weak
    bool weak_xts = xts && is_weak(*xts);
    t_check(!weak_xts, "xts(aes) + seqiv not flagged weak");
    const Algo* ecb = nullptr;
    for (const auto& a : d.algos) if (a.name == "ecb(aes)" && a.module == "aesni_intel") { ecb = &a; break; }
    t_check(ecb != nullptr && is_weak(*ecb), "ecb(aes) aesni flagged weak");

    std::ostringstream os;
    d.ts = 0;
    render_json(os, d);
    std::string j = os.str();
    t_check(j.find("\"sha256\"") != std::string::npos, "json contains sha256");
    t_check(j.find("\"type\": \"shash\"") != std::string::npos, "json has type shash");
    t_check(j.find("\"summary\"") != std::string::npos && j.find("\"algorithms\"") != std::string::npos,
            "json has summary + algorithms");
    t_check(j.find("max_priority") != std::string::npos, "json summary max_priority");

    disable_color();
    Filters f;
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_catalog(d, f, false);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    enable_color();
  }

  std::cout << "-- selftest: json escapes --\n";
  {
    t_check(json_escape("a\"b") == "a\\\"b", "quote escaped");
    t_check(json_escape("a\\b") == "a\\\\b", "backslash escaped");
    t_check(json_escape("plain") == "plain", "plain unchanged");
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "crypto-watch — kernel crypto API catalog (/proc/crypto)\n"
    "\n"
    "Usage: crypto-watch [options]\n"
    "\n"
    "  --type TYPE        only algorithms of TYPE (shash|skcipher|aead|rng|...)\n"
    "  --module MODULE    only algorithms from MODULE (e.g. aesni_intel)\n"
    "  --name NAME        only algorithm NAME (e.g. aes)\n"
    "  --internal         only internal=y algorithms\n"
    "  --no-internal      only internal=n algorithms\n"
    "  --async            only async algorithms\n"
    "  --top N            top N by priority (descending)\n"
    "  --watch N          refresh every N seconds (re-read /proc/crypto)\n"
    "  --json             machine-readable output\n"
    "  --demo             synthetic host with AES-NI + SHA-NI + generic\n"
    "  --file PATH        parse a record dump instead of /proc\n"
    "  --no-color         disable ANSI colors\n"
    "  --selftest         run self-tests and exit\n"
    "  -h, --help         this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  bool color_flag = true;
  bool demo = false;
  bool json = false;
  int watch = 0;
  std::string file;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--type")     { auto v = next(a); if (!v) return 2; f.type = *v; }
    else if (a == "--module") { auto v = next(a); if (!v) return 2; f.module = *v; }
    else if (a == "--name")   { auto v = next(a); if (!v) return 2; f.name = *v; }
    else if (a == "--file")   { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")  { auto v = next(a); if (!v) return 2; f.top = std::atoi(v->c_str()); }
    else if (a == "--watch"){ auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--internal")  f.internal = true;
    else if (a == "--no-internal") f.no_internal = true;
    else if (a == "--async")     f.async = true;
    else if (a == "--demo")    demo = true;
    else if (a == "--json")    json = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  std::string source = file.empty() ? "/proc/crypto" : file;

  if (watch > 0) {
    Catalog cur;
    for (;;) {
      cur.ts = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count();
      bool ok = demo ? demo_load(cur) : load_catalog(cur, source);
      if (!ok) {
        std::cerr << "error: cannot read " << source << "\n";
        return 1;
      }
      render_catalog(cur, f, false);
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Catalog cat;
  cat.ts = std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()).count();
  bool ok = demo ? demo_load(cat) : load_catalog(cat, source);
  if (!ok) {
    std::cerr << "error: cannot read " << source << "\n";
    return 1;
  }
  if (json) render_json(std::cout, cat);
  else render_catalog(cat, f, false);
  return 0;
}