// SPDX-License-Identifier: BUSL-1.1
// Polyglot demo - JavaScript compiled to wasm32-wasip1 via Javy.
// Prints: "js: sum(1..=100)=5050 fib(20)=6765"

function fib(n) {
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

const line = `js: sum(1..=100)=${sum} fib(20)=${fib(20)}\n`;
Javy.IO.writeSync(1, new TextEncoder().encode(line));
