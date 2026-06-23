// Polyglot example: TypeScript run via the burn script engine (oxc strip-types).
// Prints: "ts: sum(1..=100)=5050 fib(20)=6765"

function fib(n: number): number {
  if (n < 2) return n;
  let a = 0, b = 1;
  for (let i = 2; i <= n; i++) {
    const c = a + b;
    a = b;
    b = c;
  }
  return b;
}

let sum = 0;
for (let i = 1; i <= 100; i++) sum += i;

console.log(`ts: sum(1..=100)=${sum} fib(20)=${fib(20)}`);
