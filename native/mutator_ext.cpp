/*
 * Zero-Hunter-Engine - High-Performance C++17 Native Mutator & Bitmap Classifier
 * Educational & Authorized Defensive Research Only
 *
 * Exposes C ABI functions callable via Python ctypes (no Python.h dependency).
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>

namespace {

struct XorShift64 {
    uint64_t state;
    explicit XorShift64(uint64_t seed) : state(seed ? seed : 0x9e3779b97f4a7c15ULL) {}

    inline uint64_t next() {
        uint64_t x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }

    inline uint32_t bounded(uint32_t limit) {
        if (limit <= 1) return 0;
        return static_cast<uint32_t>(next() % limit);
    }
};

static const int8_t INTERESTING_8[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127
};

static const int16_t INTERESTING_16[] = {
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767
};

static const int32_t INTERESTING_32[] = {
    -2147483648LL, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647
};

static uint8_t COUNT_CLASS_LOOKUP[256];
static bool lookup_initialized = false;

static void ensure_lookup() {
    if (lookup_initialized) return;
    COUNT_CLASS_LOOKUP[0] = 0;
    COUNT_CLASS_LOOKUP[1] = 1;
    COUNT_CLASS_LOOKUP[2] = 2;
    COUNT_CLASS_LOOKUP[3] = 4;
    for (int i = 4; i <= 7; ++i)     COUNT_CLASS_LOOKUP[i] = 8;
    for (int i = 8; i <= 15; ++i)    COUNT_CLASS_LOOKUP[i] = 16;
    for (int i = 16; i <= 31; ++i)   COUNT_CLASS_LOOKUP[i] = 32;
    for (int i = 32; i <= 127; ++i)  COUNT_CLASS_LOOKUP[i] = 64;
    for (int i = 128; i <= 255; ++i) COUNT_CLASS_LOOKUP[i] = 128;
    lookup_initialized = true;
}

inline uint16_t bswap16(uint16_t v) {
    return static_cast<uint16_t>((v << 8) | (v >> 8));
}

inline uint32_t bswap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

} // namespace

extern "C" {

const char* zh_native_version() {
    return "2.0.0-cxx17";
}

/*
 * Fast AFL-style havoc mutator in C++.
 * Returns mutated payload length written into out_buf (up to max_out_len).
 */
size_t zh_mutate_havoc(
    const uint8_t* in_buf,
    size_t in_len,
    uint8_t* out_buf,
    size_t max_out_len,
    uint32_t intensity,
    uint64_t seed
) {
    if (!out_buf || max_out_len == 0) return 0;

    XorShift64 rng(seed);
    size_t cur_len = in_len;
    if (!in_buf || cur_len == 0) {
        cur_len = std::min<size_t>(16, max_out_len);
        for (size_t i = 0; i < cur_len; ++i) {
            out_buf[i] = static_cast<uint8_t>(rng.next() & 0xFFu);
        }
    } else {
        cur_len = std::min(cur_len, max_out_len);
        std::memcpy(out_buf, in_buf, cur_len);
    }

    uint32_t steps = (intensity == 0) ? (1u << (1u + rng.bounded(6))) : intensity;

    for (uint32_t s = 0; s < steps; ++s) {
        if (cur_len == 0) {
            out_buf[0] = static_cast<uint8_t>(rng.next() & 0xFFu);
            cur_len = 1;
        }

        uint32_t op = rng.bounded(14);
        switch (op) {
            case 0: { // Flip single bit
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len));
                out_buf[pos] ^= static_cast<uint8_t>(1u << rng.bounded(8));
                break;
            }
            case 1: { // Interesting 8-bit
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len));
                out_buf[pos] = static_cast<uint8_t>(
                    INTERESTING_8[rng.bounded(sizeof(INTERESTING_8) / sizeof(INTERESTING_8[0]))]
                );
                break;
            }
            case 2: { // Interesting 16-bit (LE or BE)
                if (cur_len < 2) break;
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len - 1));
                uint16_t val = static_cast<uint16_t>(
                    INTERESTING_16[rng.bounded(sizeof(INTERESTING_16) / sizeof(INTERESTING_16[0]))]
                );
                if (rng.bounded(2)) val = bswap16(val);
                std::memcpy(out_buf + pos, &val, 2);
                break;
            }
            case 3: { // Interesting 32-bit (LE or BE)
                if (cur_len < 4) break;
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len - 3));
                uint32_t val = static_cast<uint32_t>(
                    INTERESTING_32[rng.bounded(sizeof(INTERESTING_32) / sizeof(INTERESTING_32[0]))]
                );
                if (rng.bounded(2)) val = bswap32(val);
                std::memcpy(out_buf + pos, &val, 4);
                break;
            }
            case 4: { // 8-bit arithmetic +/- 1..35
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len));
                int delta = static_cast<int>(1 + rng.bounded(35));
                if (rng.bounded(2)) delta = -delta;
                out_buf[pos] = static_cast<uint8_t>(out_buf[pos] + delta);
                break;
            }
            case 5: { // 16-bit arithmetic +/- 1..35
                if (cur_len < 2) break;
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len - 1));
                uint16_t val;
                std::memcpy(&val, out_buf + pos, 2);
                bool big_endian = (rng.bounded(2) == 1);
                if (big_endian) val = bswap16(val);
                int delta = static_cast<int>(1 + rng.bounded(35));
                if (rng.bounded(2)) delta = -delta;
                val = static_cast<uint16_t>(val + delta);
                if (big_endian) val = bswap16(val);
                std::memcpy(out_buf + pos, &val, 2);
                break;
            }
            case 6: { // 32-bit arithmetic +/- 1..35
                if (cur_len < 4) break;
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len - 3));
                uint32_t val;
                std::memcpy(&val, out_buf + pos, 4);
                bool big_endian = (rng.bounded(2) == 1);
                if (big_endian) val = bswap32(val);
                int delta = static_cast<int>(1 + rng.bounded(35));
                if (rng.bounded(2)) delta = -delta;
                val = static_cast<uint32_t>(val + delta);
                if (big_endian) val = bswap32(val);
                std::memcpy(out_buf + pos, &val, 4);
                break;
            }
            case 7: { // Random byte overwrite
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len));
                out_buf[pos] ^= static_cast<uint8_t>(1 + rng.bounded(255));
                break;
            }
            case 8: { // Delete block
                if (cur_len < 4) break;
                size_t del_len = 1 + rng.bounded(static_cast<uint32_t>(std::min<size_t>(cur_len / 2, 32)));
                size_t del_from = rng.bounded(static_cast<uint32_t>(cur_len - del_len + 1));
                std::memmove(out_buf + del_from, out_buf + del_from + del_len, cur_len - del_from - del_len);
                cur_len -= del_len;
                break;
            }
            case 9:
            case 10: { // Clone or insert block
                if (cur_len >= max_out_len) break;
                size_t max_add = std::min<size_t>(max_out_len - cur_len, 64);
                size_t clone_len = 1 + rng.bounded(static_cast<uint32_t>(max_add));
                size_t clone_to = rng.bounded(static_cast<uint32_t>(cur_len + 1));
                bool actually_clone = (rng.bounded(4) != 0) && (cur_len >= clone_len);

                if (actually_clone) {
                    size_t clone_from = rng.bounded(static_cast<uint32_t>(cur_len - clone_len + 1));
                    uint8_t tmp[64];
                    std::memcpy(tmp, out_buf + clone_from, clone_len);
                    std::memmove(out_buf + clone_to + clone_len, out_buf + clone_to, cur_len - clone_to);
                    std::memcpy(out_buf + clone_to, tmp, clone_len);
                } else {
                    uint8_t fill = (rng.bounded(2) == 0)
                        ? static_cast<uint8_t>(rng.next() & 0xFFu)
                        : out_buf[rng.bounded(static_cast<uint32_t>(cur_len))];
                    std::memmove(out_buf + clone_to + clone_len, out_buf + clone_to, cur_len - clone_to);
                    std::memset(out_buf + clone_to, fill, clone_len);
                }
                cur_len += clone_len;
                break;
            }
            case 11: { // Overwrite chunk with self chunk
                if (cur_len < 4) break;
                size_t copy_len = 1 + rng.bounded(static_cast<uint32_t>(std::min<size_t>(cur_len - 1, 32)));
                size_t copy_from = rng.bounded(static_cast<uint32_t>(cur_len - copy_len + 1));
                size_t copy_to = rng.bounded(static_cast<uint32_t>(cur_len - copy_len + 1));
                if (copy_from != copy_to) {
                    std::memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
                }
                break;
            }
            case 12: { // Memset block with constant byte
                if (cur_len < 2) break;
                size_t blk_len = 1 + rng.bounded(static_cast<uint32_t>(std::min<size_t>(cur_len, 24)));
                size_t pos = rng.bounded(static_cast<uint32_t>(cur_len - blk_len + 1));
                uint8_t val = (rng.bounded(2) == 0) ? 0x00u : static_cast<uint8_t>(rng.next() & 0xFFu);
                std::memset(out_buf + pos, val, blk_len);
                break;
            }
            case 13: { // Swap two random bytes
                if (cur_len < 2) break;
                size_t a = rng.bounded(static_cast<uint32_t>(cur_len));
                size_t b = rng.bounded(static_cast<uint32_t>(cur_len));
                std::swap(out_buf[a], out_buf[b]);
                break;
            }
        }
    }

    return cur_len;
}

/*
 * Crossover splice of two corpus inputs + optional micro-havoc.
 */
size_t zh_mutate_splice(
    const uint8_t* buf_a,
    size_t len_a,
    const uint8_t* buf_b,
    size_t len_b,
    uint8_t* out_buf,
    size_t max_out_len,
    uint64_t seed
) {
    if (!out_buf || max_out_len == 0) return 0;
    if (!buf_a || len_a == 0) return zh_mutate_havoc(buf_b, len_b, out_buf, max_out_len, 4, seed);
    if (!buf_b || len_b == 0) return zh_mutate_havoc(buf_a, len_a, out_buf, max_out_len, 4, seed);

    XorShift64 rng(seed);
    size_t min_len = std::min(len_a, len_b);
    size_t split_at = (min_len > 2) ? (1 + rng.bounded(static_cast<uint32_t>(min_len - 1))) : 0;

    size_t part1 = std::min(split_at, max_out_len);
    std::memcpy(out_buf, buf_a, part1);

    size_t rem = max_out_len - part1;
    size_t part2 = (len_b > split_at) ? std::min(len_b - split_at, rem) : 0;
    if (part2 > 0) {
        std::memcpy(out_buf + part1, buf_b + split_at, part2);
    }

    size_t total = part1 + part2;
    return zh_mutate_havoc(out_buf, total, out_buf, max_out_len, 2 + rng.bounded(4), rng.next());
}

/*
 * Fast 64-bit word scan of 64KB trace_bits against virgin_bits.
 * Returns:
 *   0 -> no new coverage
 *   1 -> new hit-count bucket on existing edge
 *   2 -> brand-new edge discovered
 */
uint32_t zh_update_coverage_bitmap(
    const uint8_t* trace_bits,
    uint8_t* virgin_bits,
    size_t map_size,
    uint32_t* out_run_edges,
    uint32_t* out_new_edges
) {
    ensure_lookup();
    uint32_t ret = 0;
    uint32_t run_edges = 0;
    uint32_t new_edges = 0;

    size_t words = map_size / sizeof(uint64_t);
    const uint64_t* t64 = reinterpret_cast<const uint64_t*>(trace_bits);

    for (size_t w = 0; w < words; ++w) {
        if (t64[w] == 0ULL) continue;  // Fast skip 8 empty edge slots!
        size_t base = w * sizeof(uint64_t);
        for (size_t b = 0; b < sizeof(uint64_t); ++b) {
            uint8_t raw = trace_bits[base + b];
            if (!raw) continue;
            ++run_edges;
            uint8_t classified = COUNT_CLASS_LOOKUP[raw];
            uint8_t virgin = virgin_bits[base + b];
            if (classified & virgin) {
                if (virgin == 0xFFu) {
                    ret = 2;
                    ++new_edges;
                } else if (ret < 1) {
                    ret = 1;
                }
                virgin_bits[base + b] = static_cast<uint8_t>(virgin & ~classified);
            }
        }
    }

    if (out_run_edges) *out_run_edges = run_edges;
    if (out_new_edges) *out_new_edges = new_edges;
    return ret;
}

} // extern "C"
