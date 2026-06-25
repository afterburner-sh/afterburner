# Section 15 acceptance: database persistence using N3 (host-backed FS) and N2 threads.
#
# BURN_DB_DIR: host directory mounted as /data (set by the caller / test harness).
# BURN_DB_MODE: "write" (default) or "read".
#
# write mode - creates a sqlite3 database at /data/accept_test.db, inserts rows
#   "alpha" and "beta" concurrently from two real threads (N2), then inserts
#   "gamma" on the main thread. Prints "write-ok" on success.
#
# read mode  - reopens the same file, reads all rows, and prints them in
#   "rows=alpha,beta,gamma" format (order is by INSERT rowid). Used by the
#   acceptance test's second run to prove persistence across runtime exits (N3).

import os
import sqlite3
import threading

DB = "/data/accept_test.db"
MODE = os.environ.get("BURN_DB_MODE", "write")


def write_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, val TEXT)"
    )
    conn.commit()
    conn.close()

    errors = []

    def insert_row(val):
        try:
            c = sqlite3.connect(DB)
            c.execute("INSERT INTO items (val) VALUES (?)", (val,))
            c.commit()
            c.close()
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=insert_row, args=(v,)) for v in ("alpha", "beta")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    c = sqlite3.connect(DB)
    c.execute("INSERT INTO items (val) VALUES (?)", ("gamma",))
    c.commit()
    c.close()

    if errors:
        raise RuntimeError("concurrent insert errors: " + repr(errors))

    print("write-ok")


def read_db():
    c = sqlite3.connect(DB)
    rows = [r[0] for r in c.execute("SELECT val FROM items ORDER BY id").fetchall()]
    c.close()
    print("rows=" + ",".join(rows))


if MODE == "read":
    read_db()
else:
    write_db()
