// examples/go-multimodule: a real multi-package Go module compiled to
// wasm32-wasip1. `main` imports a second package, `geometry`, and calls its
// EXPORTED identifier; the package's unexported helper stays encapsulated.
//
// Expected stdout: "area=50 perimeter=30"
package main

import (
	"fmt"

	"go-multimodule/source/geometry"
)

func main() {
	// Cross-package calls into the exported (capitalized) API of `geometry`.
	// The lowercase helper `scale` it uses is unexported and unreachable here.
	area := geometry.RectangleArea(5, 10)
	perimeter := geometry.RectanglePerimeter(5, 10)
	fmt.Printf("area=%d perimeter=%d\n", area, perimeter)
}
