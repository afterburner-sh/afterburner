// Public header for the `geometry` translation unit. Declares the exported
// API only; the implementation file keeps its helpers private (anonymous
// namespace), so the encapsulation boundary is the header.
#pragma once

namespace geometry {

// Exported: area of an axis-aligned rectangle.
int rectangle_area(int width, int height);

// Exported: arithmetic mean (integer) of a C array.
int mean(const int* values, int count);

} // namespace geometry
