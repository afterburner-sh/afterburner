# Sibling module imported by main.py. Proves a Python package's source tree
# (entry + helper) is mounted on sys.path so `import helper` resolves.

# A leading underscore marks an internal helper that main.py does not import
# directly: it reaches fib/square, which are the package's public surface.
def _step(a, b):
    return b, a + b


def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = _step(a, b)
    return a


def square(n):
    return n * n
