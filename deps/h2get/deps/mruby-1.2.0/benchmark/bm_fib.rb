
def fib n
  return n if n < 2
  fib(n-2) + fib(n-1)
end

puts fib(37)
