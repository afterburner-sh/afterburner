# Polyglot example: Ruby on burn.
# Prints: "ruby: sum(1..=100)=5050 fib(20)=6765"

def fib(n)
  return n if n < 2
  a, b = 0, 1
  (2..n).each { a, b = b, a + b }
  b
end

total = (1..100).sum
puts "ruby: sum(1..=100)=#{total} fib(20)=#{fib(20)}"
