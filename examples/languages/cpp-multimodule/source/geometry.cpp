// Implementation of the `geometry` public API (see geometry.hpp).
//
// The anonymous namespace gives the `scale` and `accumulate_sum` helpers
// internal linkage: they are PRIVATE to this translation unit and cannot be
// referenced from main.cpp. Only the two header-declared functions are
// exported across the link boundary.
#include "geometry.hpp"

namespace {

// Private to this translation unit (internal linkage).
int scale(int a, int b) {
    return a * b;
}

// Private to this translation unit (internal linkage).
int accumulate_sum(const int* values, int count) {
    int total = 0;
    for (int i = 0; i < count; ++i) {
        total += values[i];
    }
    return total;
}

} // namespace

namespace geometry {

int rectangle_area(int width, int height) {
    return scale(width, height);
}

int mean(const int* values, int count) {
    if (count == 0) {
        return 0;
    }
    return accumulate_sum(values, count) / count;
}

} // namespace geometry
