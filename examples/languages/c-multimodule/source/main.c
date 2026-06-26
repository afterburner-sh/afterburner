/* examples/c-multimodule: a real multi-file C package compiled to a
 * wasm32-wasip1 WASI command module (real main, linked against wasi-libc) by
 * the wasi-sdk clang. main.c and geometry.c are separate translation units
 * sharing geometry.h; geometry.c's `static` helpers are encapsulated and
 * unreachable from here.
 *
 * Expected stdout: "area=50 mean=20" */
#include <stdio.h>

#include "geometry.h"

int main(void) {
    /* Cross-translation-unit calls into the exported `geometry` API. */
    int area = rectangle_area(5, 10);

    int values[] = {10, 20, 30};
    int avg = mean(values, 3);

    printf("area=%d mean=%d\n", area, avg);
    return 0;
}
