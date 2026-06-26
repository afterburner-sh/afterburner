// examples/cpp-multimodule: a real multi-file C++ package compiled to a
// wasm32-wasip1 WASI command module by the wasi-sdk clang++. `main.cpp` and
// `geometry.cpp` are separate translation units sharing `geometry.hpp`;
// `geometry.cpp`'s anonymous-namespace helpers are encapsulated (internal
// linkage) and unreachable from here.
//
// Expected stdout: "area=50 mean=20"
#include <cstdio>

#include "geometry.hpp"

int main() {
    // Cross-translation-unit calls into the exported `geometry` API.
    const int area = geometry::rectangle_area(5, 10);

    const int values[] = {10, 20, 30};
    const int mean = geometry::mean(values, 3);

    std::printf("area=%d mean=%d\n", area, mean);
    return 0;
}
