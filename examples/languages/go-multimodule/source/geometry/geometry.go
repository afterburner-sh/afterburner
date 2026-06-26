// Package geometry is a SECOND Go package in this module, imported by main.
// It demonstrates Go's identifier-case encapsulation: capitalized identifiers
// (RectangleArea, RectanglePerimeter) are exported across the package
// boundary; the lowercase `scale` is package-private and cannot be named by
// `main`.
package geometry

// RectangleArea is exported: callable from other packages.
func RectangleArea(width, height int) int {
	return scale(width, height)
}

// RectanglePerimeter is exported.
func RectanglePerimeter(width, height int) int {
	return 2 * (width + height)
}

// scale is unexported (lowercase): internal to this package only.
func scale(a, b int) int {
	return a * b
}
