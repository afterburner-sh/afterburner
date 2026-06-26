# Multi-module Ruby example for burn: the entry requires a sibling module.
# Prints: "ruby-mm: fib(10)=55 square(7)=49"
require 'helper'

puts "ruby-mm: fib(10)=#{Helper.fib(10)} square(7)=#{Helper.square(7)}"
