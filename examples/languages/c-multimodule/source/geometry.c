/* Implementation of the `geometry` public API (see geometry.h).
 *
 * `scale` and `accumulate_sum` are `static`: internal linkage makes them
 * PRIVATE to this translation unit. main.c cannot reference them; it sees
 * only the two functions declared in geometry.h. */
#include "geometry.h"

/* Private to this translation unit (static = internal linkage). */
static int scale(int a, int b) {
    return a * b;
}

/* Private to this translation unit. */
static int accumulate_sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        total += values[i];
    }
    return total;
}

int rectangle_area(int width, int height) {
    return scale(width, height);
}

int mean(const int *values, int count) {
    if (count == 0) {
        return 0;
    }
    return accumulate_sum(values, count) / count;
}
