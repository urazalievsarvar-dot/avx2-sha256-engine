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
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void store_be32(uint8_t* p, uint32_t x) {
    p[0] = uint8_t(x >> 24); p[1] = uint8_t(x >> 16); p[2] = uint8_t(x >> 8); p[3] = uint8_t(x);
}

struct Context {
    std::array<uint32_t,8> h{0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    std::array<uint8_t,64> buffer{};
    uint64_t total_len = 0;
    size_t buffer_len = 0;
};

void compress(std::array<uint32_t,8>& h, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i=0;i<16;++i) w[i] = load_be32(block + i*4);
    for (int i=16;i<64;++i) {
        const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i=0;i<64;++i) {
        const uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
        const uint32_t ch = (e&f)^((~e)&g);
        const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
        const uint32_t maj = (a&b)^(a&c)^(b&c);
        const uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void update(Context& ctx, const uint8_t* data, size_t len) {
    ctx.total_len += len;
    while (len > 0) {
        const size_t n = std::min(len, 64 - ctx.buffer_len);
        std::memcpy(ctx.buffer.data()+ctx.buffer_len, data, n);
        ctx.buffer_len += n; data += n; len -= n;
        if (ctx.buffer_len == 64) { compress(ctx.h, ctx.buffer.data()); ctx.buffer_len = 0; }
    }
}

std::array<uint8_t,32> final(Context ctx) {
    const uint64_t bit_len = ctx.total_len * 8u;
    ctx.buffer[ctx.buffer_len++] = 0x80;
    if (ctx.buffer_len > 56) {
        std::fill(ctx.buffer.begin()+ctx.buffer_len, ctx.buffer.end(), 0);
        compress(ctx.h, ctx.buffer.data());
        ctx.buffer_len = 0;
    }
    std::fill(ctx.buffer.begin()+ctx.buffer_len, ctx.buffer.begin()+56, 0);
    for (int i=0;i<8;++i) ctx.buffer[63-i] = uint8_t(bit_len >> (8*i));
    compress(ctx.h, ctx.buffer.data());
    std::array<uint8_t,32> out{};
    for (int i=0;i<8;++i) store_be32(out.data()+i*4, ctx.h[i]);
    return out;
}

std::array<uint8_t,32> hash(const uint8_t* data, size_t len) {
    Context c; update(c,data,len); return final(c);
}
std::array<uint8_t,32> double_hash(const uint8_t* data, size_t len) {
    const auto a = hash(data,len); return hash(a.data(),a.size());
}
}

std::string hex_be(const std::array<uint8_t,32>& x) {
    std::ostringstream os; os << std::hex << std::setfill('0');
    for (uint8_t b: x) os << std::setw(2) << unsigned(b);
    return os.str();
}
std::string hex_reversed(const std::array<uint8_t,32>& x) {
    std::ostringstream os; os << std::hex << std::setfill('0');
    for (auto it=x.rbegin(); it!=x.rend(); ++it) os << std::setw(2) << unsigned(*it);
    return os.str();
}

bool from_hex(const std::string& s, uint8_t* out, size_t n) {
    if (s.size()!=n*2) return false;
    auto val=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
    for(size_t i=0;i<n;++i){ int a=val(s[2*i]),b=val(s[2*i+1]); if(a<0||b<0)return false; out[i]=uint8_t((a<<4)|b); }
    return true;
}

int main() {
    std::cout << "============================================================\n";
    std::cout << " DEMO V6 BUILD 028 - CORRECTNESS BASELINE + REAL BENCHMARK\n";
    std::cout << "============================================================\n";

    const std::string abc = "abc";
    const auto abc_hash = sha256::hash(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
    const std::string abc_expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const bool abc_ok = hex_be(abc_hash) == abc_expected;
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
    const auto genesis_hash = sha256::double_hash(genesis.data(), genesis.size());
    const std::string genesis_expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const bool genesis_ok = hex_reversed(genesis_hash) == genesis_expected;
    std::cout << "[TEST] Bitcoin genesis header: " << (genesis_ok ? "PASS" : "FAIL") << "\n";
    std::cout << "[TEST] Genesis hash: " << hex_reversed(genesis_hash) << "\n";

    if (!abc_ok || !genesis_ok) {
        std::cerr << "Correctness tests failed. Benchmark aborted.\n";
        return 1;
    }

    constexpr uint32_t HASHES_PER_RUN = 1'000'000;
    constexpr int WARMUP_RUNS = 1;
    constexpr int MEASURED_RUNS = 7;
    std::array<uint8_t,80> header = genesis;
    volatile uint64_t sink = 0;

    auto run_once = [&](uint32_t base_nonce) {
        const auto start = std::chrono::steady_clock::now();
        uint64_t accumulator = 0;
        std::array<uint8_t,32> last{};
        for (uint32_t i=0;i<HASHES_PER_RUN;++i) {
            const uint32_t nonce = base_nonce + i;
            header[76]=uint8_t(nonce); header[77]=uint8_t(nonce>>8); header[78]=uint8_t(nonce>>16); header[79]=uint8_t(nonce>>24);
            last = sha256::double_hash(header.data(), header.size());
            accumulator ^= (uint64_t(last[0]) << 56) | (uint64_t(last[7]) << 48) |
                           (uint64_t(last[15]) << 40) | (uint64_t(last[23]) << 32) |
                           (uint64_t(last[24]) << 24) | (uint64_t(last[27]) << 16) |
                           (uint64_t(last[30]) << 8) | uint64_t(last[31]);
        }
        sink ^= accumulator;
        const auto end = std::chrono::steady_clock::now();
        const double sec = std::chrono::duration<double>(end-start).count();
        return std::tuple<double,uint64_t,std::array<uint8_t,32>>(sec,accumulator,last);
    };

    std::cout << "\nWarm-up runs: " << WARMUP_RUNS << "\n";
    for(int i=0;i<WARMUP_RUNS;++i) run_once(uint32_t(i)*HASHES_PER_RUN);

    std::vector<double> rates;
    rates.reserve(MEASURED_RUNS);
    uint64_t final_acc=0; std::array<uint8_t,32> final_hash{};
    for(int r=0;r<MEASURED_RUNS;++r) {
        auto [sec,acc,last] = run_once(uint32_t((r+WARMUP_RUNS)*HASHES_PER_RUN));
        const double mhs = (double(HASHES_PER_RUN)/sec)/1e6;
        rates.push_back(mhs); final_acc ^= acc; final_hash = last;
        std::cout << "Run " << (r+1) << ": " << std::fixed << std::setprecision(6) << sec
                  << " s, " << std::setprecision(3) << mhs << " MH/s\n";
    }

    std::vector<double> sorted=rates; std::sort(sorted.begin(),sorted.end());
    const double median=sorted[sorted.size()/2];
    const double mean=std::accumulate(rates.begin(),rates.end(),0.0)/rates.size();
    double var=0.0; for(double x:rates) var+=(x-mean)*(x-mean); var/=rates.size();
    const double stdev=std::sqrt(var);

    std::cout << "\n============================================================\n";
    std::cout << "REAL DOUBLE SHA-256 BENCHMARK RESULT\n";
    std::cout << "Hashes per measured run: " << HASHES_PER_RUN << "\n";
    std::cout << "Measured runs: " << MEASURED_RUNS << "\n";
    std::cout << "Median: " << std::fixed << std::setprecision(3) << median << " MH/s\n";
    std::cout << "Mean:   " << mean << " MH/s\n";
    std::cout << "StdDev: " << stdev << " MH/s\n";
    std::cout << "Min:    " << *std::min_element(rates.begin(),rates.end()) << " MH/s\n";
    std::cout << "Max:    " << *std::max_element(rates.begin(),rates.end()) << " MH/s\n";
    std::cout << "Accumulator: 0x" << std::hex << std::setw(16) << std::setfill('0') << final_acc << std::dec << "\n";
    std::cout << "Final hash (internal SHA order): " << hex_be(final_hash) << "\n";
    std::cout << "Final hash (Bitcoin display):    " << hex_reversed(final_hash) << "\n";
    std::cout << "Optimization sink: 0x" << std::hex << sink << std::dec << "\n";
    std::cout << "============================================================\n";
    return 0;
}
