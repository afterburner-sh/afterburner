# Polyglot example: Python on burn.
# Prints: "python: sum(1..=100)=5050 fib(20)=6765"


def fib(n):
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


total = sum(range(1, 101))
print(f"python: sum(1..=100)={total} fib(20)={fib(20)}")
