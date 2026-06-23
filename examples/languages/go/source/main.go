// Polyglot example: Go compiled to wasm32-wasip1.
// Prints: "go: sum(1..=100)=5050 fib(20)=6765"
package main

import "fmt"

func fib(n uint64) uint64 {
	if n < 2 {
		return n
	}
	a, b := uint64(0), uint64(1)
	for i := uint64(2); i <= n; i++ {
		a, b = b, a+b
	}
	return b
}

func main() {
	var sum uint64
	for i := uint64(1); i <= 100; i++ {
		sum += i
	}
	fmt.Printf("go: sum(1..=100)=%d fib(20)=%d\n", sum, fib(20))
}
