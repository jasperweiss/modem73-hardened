#pragma once

#include <cmath>
#include <cstddef>
#include <vector>

// A non-finite sample becomes 0. Finite audio is unchanged.
inline float finite_sample(float x) {
    return std::isfinite(x) ? x : 0.f;
}

// Pointer to n elements at pos, or null when that slice is outside buf.
// The size test is first so size - n does not wrap.
template <class T>
const T* window_at(const std::vector<T>& buf, size_t pos, size_t n) {
    if (n > buf.size() || pos > buf.size() - n)
        return nullptr;
    return buf.data() + pos;
}
