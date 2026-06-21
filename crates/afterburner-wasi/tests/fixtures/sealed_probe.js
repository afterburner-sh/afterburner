// A small, self-contained fixture package for the sealed precompiled-WASM path
// test (afterburner-wasi/tests/sealed_precompiled.rs). Pure, deterministic
// compute with no host capabilities - exactly the "sealed" profile the
// self-contained WASM flavor targets. Exercises JSON in/out, a builtin
// (TextEncoder), an array fold, and an explicit error path so the
// precompiled-vs-source equality check is meaningful.
module.exports = (input) => {
  const op = input && input.op;
  if (op === "sum") {
    const xs = Array.isArray(input.values) ? input.values : [];
    let s = 0;
    for (const x of xs) s += Number(x) || 0;
    return { ok: true, sum: s, count: xs.length };
  }
  if (op === "bytelen") {
    const bytes = new TextEncoder().encode(String(input.text == null ? "" : input.text));
    return { ok: true, len: bytes.length };
  }
  return { ok: false, error: "unknown op " + String(op) };
};
