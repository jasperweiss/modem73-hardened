// Fuzz the demodulator kernels on fixed-length finite windows.
// Lengths are the ones the modems pass in. The input chooses values, not sizes.
// A quiet run means these shapes stayed inside AddressSanitizer and
// UndefinedBehaviorSanitizer. It does not say a short buffer is safe.

#include <cassert>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "phy/mfsk_modem.hh"
#include "polar_list_decoder.hh"

// MFSK decimates 1536 samples by 8. Robust NFFT is 640.
// OFDM symbol_len at 48000 Hz is (rate/300)*40.
static constexpr int kMfskDsym = MFSKParams::SYMBOL_LEN / 8;
static constexpr int kRobustNfft = 640;
static constexpr int kOfdmSymbol = (48000 / 300) * 40;
static_assert(kMfskDsym == 192, "MFSK decimated symbol");
static_assert(kRobustNfft == 640, "robust FFT");
static_assert(kOfdmSymbol == 6400, "OFDM symbol at 48000 Hz");

static volatile float g_sink;

static void keep(float x) {
    g_sink = x;
}

struct Bytes {
    const uint8_t* p;
    size_t n;
    size_t i = 0;

    uint8_t next() {
        return i < n ? p[i++] : 0;
    }

    uint32_t u32() {
        uint32_t v = next();
        v |= (uint32_t)next() << 8;
        v |= (uint32_t)next() << 16;
        v |= (uint32_t)next() << 24;
        return v;
    }

    float finite() {
        float x;
        uint32_t u = u32();
        std::memcpy(&x, &u, sizeof x);
        return std::isfinite(x) ? x : 0.f;
    }

    int16_t i16() {
        return (int16_t)(next() | ((unsigned)next() << 8));
    }
};

template <int N, int Sign>
static void run_fft(const DSP::Complex<float>* in) {
    static DSP::FastFourierTransform<N, DSP::Complex<float>, Sign> fft;
    static DSP::Complex<float> out[N];
    fft(out, in);
    float acc = 0.f;
    for (int i = 0; i < N; ++i)
        acc += out[i].real() + out[i].imag();
    keep(acc);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Bytes in{data, size};

    static DSP::Complex<float> spec[kOfdmSymbol];
    for (int i = 0; i < kOfdmSymbol; ++i)
        spec[i] = DSP::Complex<float>(in.finite(), in.finite());

    // MFSK builds only the forward transform. Robust and OFDM build both signs.
    run_fft<kMfskDsym, -1>(spec);
    run_fft<kRobustNfft, -1>(spec);
    run_fft<kRobustNfft, 1>(spec);
    run_fft<kOfdmSymbol, -1>(spec);
    run_fft<kOfdmSymbol, 1>(spec);

    static std::complex<float> z[kMfskDsym];
    static float real[kMfskDsym];
    for (int i = 0; i < kMfskDsym; ++i) {
        z[i] = std::complex<float>(in.finite(), in.finite());
        real[i] = in.finite();
    }
    float bin = in.finite();
    keep(mfsk_detail::dft_mag2(z, kMfskDsym, bin));
    keep(mfsk_detail::goertzel_mag2(real, kMfskDsym, bin));

    int steps = 1 + (int)(in.u32() % (uint32_t)mfsk_detail::ViterbiDecoder::MAX_STEPS);
    mfsk_detail::ViterbiDecoder viterbi;
    viterbi.reset();
    for (int s = 0; s < steps; ++s)
        viterbi.step(in.finite(), in.finite());
    // finish() sizes its byte buffer as data_bits/8 and then indexes it
    // for every bit. A multiple of 8 keeps that buffer in range.
    int data_bits = steps & ~7;
    auto decoded = viterbi.finish(data_bits);
    if (!decoded.empty())
        keep(decoded[0]);

    // One list decoder, the width the modems use. The frozen table is the
    // full 14-bit code so a shorter array is never passed in.
    static constexpr int kLevels[] = {8, 10, 13, 14};
    static constexpr int kMaxN = 1 << 14;
    static CODE::PolarListDecoder<SIMD<int16_t, 32>, 14> polar;
    static SIMD<int16_t, 32> mesg[kMaxN];
    static int16_t codeword[kMaxN];
    static uint32_t frozen[kMaxN / 32];

    for (int i = 0; i < kMaxN; ++i)
        codeword[i] = in.i16();
    for (size_t i = 0; i < sizeof frozen / sizeof frozen[0]; ++i)
        frozen[i] = in.u32();

    for (int level : kLevels) {
        int n = 1 << level;
        std::memset(mesg, 0, sizeof mesg);
        polar(nullptr, mesg, codeword, frozen, level);
        keep(mesg[0].v[0]);
        keep(mesg[n - 1].v[0]);
    }
    return 0;
}
