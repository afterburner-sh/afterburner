# Sibling module required by main.rb. Proves a Ruby package's source tree
# (entry + helper) is on $LOAD_PATH so `require 'helper'` resolves.
module Helper
  # An internal helper that main.rb does not call directly; it reaches the
  # module-level fib/square, the package's public surface.
  def self._step(a, b)
    [b, a + b]
  end

  def self.fib(n)
    a, b = 0, 1
    n.times { a, b = _step(a, b) }
    a
  end

  def self.square(n)
    n * n
  end
end
