// SPDX-License-Identifier: BUSL-1.1
// Polyglot demo - TypeScript compiled to JS then wasm32-wasip1 via Javy.
// Prints: "ts: sum(1..=100)=5050 fib(20)=6765"

// Javy is injected as a global by the Javy runtime; declare it for tsc.
declare const Javy: { IO: { writeSync(fd: number, buf: Uint8Array): number } };

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

const line: string = `ts: sum(1..=100)=${sum} fib(20)=${fib(20)}\n`;
Javy.IO.writeSync(1, new TextEncoder().encode(line));
