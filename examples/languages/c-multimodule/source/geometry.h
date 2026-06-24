/* Public header for the `geometry` translation unit: declares the exported
 * API only. The implementation file keeps its helper `static` (internal
 * linkage), so it is private to that file and not part of this interface. */
#ifndef GEOMETRY_H
#define GEOMETRY_H

/* Exported: area of an axis-aligned rectangle. */
int rectangle_area(int width, int height);

/* Exported: integer arithmetic mean of an array. */
int mean(const int *values, int count);

#endif /* GEOMETRY_H */
