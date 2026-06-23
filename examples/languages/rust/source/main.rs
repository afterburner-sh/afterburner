// Polyglot example: Rust compiled to wasm32-wasip1.
// Prints: "rust: sum(1..=100)=5050 fib(20)=6765"

fn fib(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut a = 0u64;
    let mut b = 1u64;
    for _ in 2..=n {
        let c = a + b;
        a = b;
        b = c;
    }
    b
}

fn main() {
    let sum: u64 = (1u64..=100).sum();
    let f20 = fib(20);
    println!("rust: sum(1..=100)={sum} fib(20)={f20}");
}
