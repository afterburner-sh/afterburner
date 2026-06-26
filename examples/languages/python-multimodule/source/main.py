# Multi-module Python example for burn: the entry imports a sibling module.
# Prints: "python-mm: fib(10)=55 square(7)=49"
from helper import fib, square

print(f"python-mm: fib(10)={fib(10)} square(7)={square(7)}")
