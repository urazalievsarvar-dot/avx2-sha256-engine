#include <array>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace sha256 {

constexpr std::array<uint32_t, 8> IV = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }
inline uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void store_be32(uint8_t* p, uint32_t x) {
    p[0] = uint8_t(x >> 24); p[1] = uint8_t(x >> 16);
    p[2] = uint8_t(x >> 8);  p[3] = uint8_t(x);
}

void compress(std::array<uint32_t,8>& h, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

struct Context {
    std::array<uint32_t,8> h = IV;
    std::array<uint8_t,64> buffer{};
    uint64_t total_len = 0;
    size_t buffer_len = 0;
};

void update(Context& ctx, const uint8_t* data, size_t len) {
    ctx.total_len += len;
    while (len > 0) {
        const size_t n = std::min(len, 64 - ctx.buffer_len);
        std::memcpy(ctx.buffer.data() + ctx.buffer_len, data, n);
        ctx.buffer_len += n; data += n; len -= n;
        if (ctx.buffer_len == 64) {
            compress(ctx.h, ctx.buffer.data());
            ctx.buffer_len = 0;
        }
    }
}

std::array<uint8_t,32> final(Context ctx) {
    const uint64_t bit_len = ctx.total_len * 8u;
    ctx.buffer[ctx.buffer_len++] = 0x80;
    if (ctx.buffer_len > 56) {
        std::fill(ctx.buffer.begin() + ctx.buffer_len, ctx.buffer.end(), 0);
        compress(ctx.h, ctx.buffer.data());
        ctx.buffer_len = 0;
    }
    std::fill(ctx.buffer.begin() + ctx.buffer_len, ctx.buffer.begin() + 56, 0);
    for (int i = 0; i < 8; ++i) ctx.buffer[63-i] = uint8_t(bit_len >> (8*i));
    compress(ctx.h, ctx.buffer.data());
    std::array<uint8_t,32> out{};
    for (int i = 0; i < 8; ++i) store_be32(out.data() + i*4, ctx.h[i]);
    return out;
}

std::array<uint8_t,32> hash(const uint8_t* data, size_t len) {
    Context c; update(c, data, len); return final(c);
}
std::array<uint8_t,32> double_hash(const uint8_t* data, size_t len) {
    const auto first = hash(data, len);
    return hash(first.data(), first.size());
}

// Bitcoin 80-byte header specialization. The first 64 bytes are fixed,
// so their compression result (midstate) is computed once.
struct BitcoinHeaderMidstate {
    std::array<uint32_t,8> midstate{};
    std::array<uint8_t,12> tail{}; // bytes 64..75: merkle tail, time, bits
};

BitcoinHeaderMidstate prepare_header_midstate(const uint8_t header80[80]) {
    BitcoinHeaderMidstate p;
    p.midstate = IV;
    compress(p.midstate, header80);
    std::memcpy(p.tail.data(), header80 + 64, p.tail.size());
    return p;
}

std::array<uint8_t,32> double_hash_header_midstate(
    const BitcoinHeaderMidstate& p, uint32_t nonce)
{
    // Complete first SHA-256: second 64-byte block contains bytes 64..79,
    // then padding, then the 80-byte message length (640 bits).
    std::array<uint8_t,64> block2{};
    std::memcpy(block2.data(), p.tail.data(), p.tail.size());
    block2[12] = uint8_t(nonce);
    block2[13] = uint8_t(nonce >> 8);
    block2[14] = uint8_t(nonce >> 16);
    block2[15] = uint8_t(nonce >> 24);
    block2[16] = 0x80;
    block2[62] = 0x02;
    block2[63] = 0x80; // 640 bits

    auto first_state = p.midstate;
    compress(first_state, block2.data());

    // Second SHA-256 over the 32-byte first digest.
    std::array<uint8_t,64> second_block{};
    for (int i = 0; i < 8; ++i) store_be32(second_block.data() + i*4, first_state[i]);
    second_block[32] = 0x80;
    second_block[62] = 0x01;
    second_block[63] = 0x00; // 256 bits

    auto second_state = IV;
    compress(second_state, second_block.data());

    std::array<uint8_t,32> out{};
    for (int i = 0; i < 8; ++i) store_be32(out.data() + i*4, second_state[i]);
    return out;
}

} // namespace sha256

std::string hex_be(const std::array<uint8_t,32>& x) {
    std::ostringstream os; os << std::hex << std::setfill('0');
    for (uint8_t b : x) os << std::setw(2) << unsigned(b);
    return os.str();
}
std::string hex_reversed(const std::array<uint8_t,32>& x) {
    std::ostringstream os; os << std::hex << std::setfill('0');
    for (auto it = x.rbegin(); it != x.rend(); ++it) os << std::setw(2) << unsigned(*it);
    return os.str();
}
bool from_hex(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != n * 2) return false;
    auto val=[](char c)->int {
        if(c>='0'&&c<='9') return c-'0';
        if(c>='a'&&c<='f') return c-'a'+10;
        if(c>='A'&&c<='F') return c-'A'+10;
        return -1;
    };
    for(size_t i=0;i<n;++i) {
        int a=val(s[2*i]), b=val(s[2*i+1]);
        if(a<0||b<0) return false;
        out[i]=uint8_t((a<<4)|b);
    }
    return true;
}

struct Stats {
    double median = 0;
    double mean = 0;
    double stdev = 0;
    double min = 0;
    double max = 0;
};

Stats calculate_stats(const std::vector<double>& rates) {
    std::vector<double> sorted = rates;
    std::sort(sorted.begin(), sorted.end());
    Stats s;
    s.median = sorted[sorted.size()/2];
    s.mean = std::accumulate(rates.begin(), rates.end(), 0.0) / rates.size();
    double var = 0.0;
    for (double x : rates) var += (x-s.mean)*(x-s.mean);
    var /= rates.size();
    s.stdev = std::sqrt(var);
    s.min = *std::min_element(rates.begin(), rates.end());
    s.max = *std::max_element(rates.begin(), rates.end());
    return s;
}

int main() {
    std::cout << "============================================================\n";
    std::cout << " DEMO V6 BUILD 028 - VERIFIED MIDSTATE OPTIMIZATION\n";
    std::cout << "============================================================\n";

    const std::string abc = "abc";
    const auto abc_hash = sha256::hash(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
    const bool abc_ok = hex_be(abc_hash) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::cout << "[TEST] SHA256(\"abc\"): " << (abc_ok ? "PASS" : "FAIL") << "\n";

    const std::string genesis_hex =
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c";
    std::array<uint8_t,80> genesis{};
    if (!from_hex(genesis_hex, genesis.data(), genesis.size())) return 2;

    const auto genesis_generic = sha256::double_hash(genesis.data(), genesis.size());
    const std::string genesis_expected =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const bool genesis_ok = hex_reversed(genesis_generic) == genesis_expected;
    std::cout << "[TEST] Bitcoin genesis header: " << (genesis_ok ? "PASS" : "FAIL") << "\n";
    std::cout << "[TEST] Genesis hash: " << hex_reversed(genesis_generic) << "\n";

    const auto prepared = sha256::prepare_header_midstate(genesis.data());
    const uint32_t genesis_nonce = uint32_t(genesis[76]) |
                                   (uint32_t(genesis[77]) << 8) |
                                   (uint32_t(genesis[78]) << 16) |
                                   (uint32_t(genesis[79]) << 24);
    const auto genesis_optimized = sha256::double_hash_header_midstate(prepared, genesis_nonce);
    const bool optimized_genesis_ok = genesis_optimized == genesis_generic;
    std::cout << "[TEST] Midstate genesis equality: "
              << (optimized_genesis_ok ? "PASS" : "FAIL") << "\n";

    bool nonce_equivalence_ok = true;
    constexpr std::array<uint32_t,8> TEST_NONCES = {
        0u, 1u, 2u, 42u, 0x12345678u, 0x7fffffffu, 0x80000000u, 0xffffffffu
    };
    for (uint32_t nonce : TEST_NONCES) {
        auto header = genesis;
        header[76]=uint8_t(nonce); header[77]=uint8_t(nonce>>8);
        header[78]=uint8_t(nonce>>16); header[79]=uint8_t(nonce>>24);
        const auto generic = sha256::double_hash(header.data(), header.size());
        const auto optimized = sha256::double_hash_header_midstate(prepared, nonce);
        if (generic != optimized) {
            nonce_equivalence_ok = false;
            std::cerr << "Mismatch at nonce " << nonce << "\n";
            break;
        }
    }
    std::cout << "[TEST] Midstate nonce equivalence (8 vectors): "
              << (nonce_equivalence_ok ? "PASS" : "FAIL") << "\n";

    if (!abc_ok || !genesis_ok || !optimized_genesis_ok || !nonce_equivalence_ok) {
        std::cerr << "Correctness tests failed. Benchmark aborted.\n";
        return 1;
    }

    constexpr uint32_t HASHES_PER_RUN = 1'000'000;
    constexpr int WARMUP_RUNS = 1;
    constexpr int MEASURED_RUNS = 7;
    volatile uint64_t sink = 0;

    auto generic_run = [&](uint32_t base_nonce) {
        auto header = genesis;
        const auto start = std::chrono::steady_clock::now();
        uint64_t accumulator = 0;
        std::array<uint8_t,32> last{};
        for (uint32_t i=0; i<HASHES_PER_RUN; ++i) {
            const uint32_t nonce = base_nonce + i;
            header[76]=uint8_t(nonce); header[77]=uint8_t(nonce>>8);
            header[78]=uint8_t(nonce>>16); header[79]=uint8_t(nonce>>24);
            last = sha256::double_hash(header.data(), header.size());
            accumulator ^= (uint64_t(last[0]) << 56) | (uint64_t(last[7]) << 48) |
                           (uint64_t(last[15]) << 40) | (uint64_t(last[23]) << 32) |
                           (uint64_t(last[24]) << 24) | (uint64_t(last[27]) << 16) |
                           (uint64_t(last[30]) << 8) | uint64_t(last[31]);
        }
        sink ^= accumulator;
        const double sec = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
        return std::tuple<double,uint64_t,std::array<uint8_t,32>>(sec, accumulator, last);
    };

    auto optimized_run = [&](uint32_t base_nonce) {
        const auto start = std::chrono::steady_clock::now();
        uint64_t accumulator = 0;
        std::array<uint8_t,32> last{};
        for (uint32_t i=0; i<HASHES_PER_RUN; ++i) {
            const uint32_t nonce = base_nonce + i;
            last = sha256::double_hash_header_midstate(prepared, nonce);
            accumulator ^= (uint64_t(last[0]) << 56) | (uint64_t(last[7]) << 48) |
                           (uint64_t(last[15]) << 40) | (uint64_t(last[23]) << 32) |
                           (uint64_t(last[24]) << 24) | (uint64_t(last[27]) << 16) |
                           (uint64_t(last[30]) << 8) | uint64_t(last[31]);
        }
        sink ^= accumulator;
        const double sec = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count();
        return std::tuple<double,uint64_t,std::array<uint8_t,32>>(sec, accumulator, last);
    };

    std::cout << "\nWarm-up: generic + midstate optimized\n";
    generic_run(0);
    optimized_run(0);

    std::vector<double> generic_rates, optimized_rates;
    generic_rates.reserve(MEASURED_RUNS);
    optimized_rates.reserve(MEASURED_RUNS);
    uint64_t generic_acc = 0, optimized_acc = 0;
    std::array<uint8_t,32> generic_last{}, optimized_last{};

    for (int r=0; r<MEASURED_RUNS; ++r) {
        const uint32_t base = uint32_t((r + WARMUP_RUNS) * HASHES_PER_RUN);
        auto [generic_sec, ga, gh] = generic_run(base);
        auto [optimized_sec, oa, oh] = optimized_run(base);
        const double generic_mhs = (double(HASHES_PER_RUN)/generic_sec)/1e6;
        const double optimized_mhs = (double(HASHES_PER_RUN)/optimized_sec)/1e6;
        generic_rates.push_back(generic_mhs);
        optimized_rates.push_back(optimized_mhs);
        generic_acc ^= ga; optimized_acc ^= oa;
        generic_last = gh; optimized_last = oh;
        std::cout << "Run " << (r+1)
                  << ": generic " << std::fixed << std::setprecision(3) << generic_mhs
                  << " MH/s | midstate " << optimized_mhs << " MH/s\n";
    }

    const Stats generic_stats = calculate_stats(generic_rates);
    const Stats optimized_stats = calculate_stats(optimized_rates);
    const double speedup = optimized_stats.median / generic_stats.median;
    const double increase = (speedup - 1.0) * 100.0;
    const bool benchmark_outputs_match = (generic_acc == optimized_acc) &&
                                         (generic_last == optimized_last);

    std::cout << "\n============================================================\n";
    std::cout << "BUILD 028 VERIFIED BENCHMARK RESULT\n";
    std::cout << "Hashes per measured run: " << HASHES_PER_RUN << "\n";
    std::cout << "Measured runs: " << MEASURED_RUNS << "\n\n";

    std::cout << "GENERIC DOUBLE SHA-256\n";
    std::cout << "Median: " << std::fixed << std::setprecision(3) << generic_stats.median << " MH/s\n";
    std::cout << "Mean:   " << generic_stats.mean << " MH/s\n";
    std::cout << "StdDev: " << generic_stats.stdev << " MH/s\n";
    std::cout << "Min:    " << generic_stats.min << " MH/s\n";
    std::cout << "Max:    " << generic_stats.max << " MH/s\n\n";

    std::cout << "MIDSTATE-OPTIMIZED DOUBLE SHA-256\n";
    std::cout << "Median: " << optimized_stats.median << " MH/s\n";
    std::cout << "Mean:   " << optimized_stats.mean << " MH/s\n";
    std::cout << "StdDev: " << optimized_stats.stdev << " MH/s\n";
    std::cout << "Min:    " << optimized_stats.min << " MH/s\n";
    std::cout << "Max:    " << optimized_stats.max << " MH/s\n\n";

    std::cout << "Verified speedup: " << std::setprecision(3) << speedup << "x\n";
    std::cout << "Verified increase: " << std::setprecision(2) << increase << "%\n";
    std::cout << "Benchmark output equality: "
              << (benchmark_outputs_match ? "PASS" : "FAIL") << "\n";
    std::cout << "Accumulator: 0x" << std::hex << std::setw(16) << std::setfill('0')
              << optimized_acc << std::dec << "\n";
    std::cout << "Final hash (internal SHA order): " << hex_be(optimized_last) << "\n";
    std::cout << "Final hash (Bitcoin display):    " << hex_reversed(optimized_last) << "\n";
    std::cout << "Optimization sink: 0x" << std::hex << sink << std::dec << "\n";
    std::cout << "============================================================\n";

    return benchmark_outputs_match ? 0 : 3;
}
