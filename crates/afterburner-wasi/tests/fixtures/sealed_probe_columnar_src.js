// Columnar fixture: for each row, sum c0[i] + c1[i] into result column "sum".
module.exports = (batch) => {
  const c0 = batch.columns.c0;
  const c1 = batch.columns.c1;
  const out = new Int32Array(batch.row_count);
  for (let i = 0; i < batch.row_count; i++) out[i] = c0[i] + c1[i];
  return { row_count: batch.row_count, columns: { sum: out } };
};
