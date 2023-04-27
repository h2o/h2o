assert('while expression', '11.5.2.3.2') do
  idx = 10
  all = []
  res = while idx > 0
    all << idx
    idx -= 1
  end

  assert_equal nil, res
  assert_equal [10,9,8,7,6,5,4,3,2,1], all
end

assert('until expression', '11.5.2.3.3') do
  idx = 10
  all = []
  res = until idx == 0
    all << idx
    idx -= 1
  end

  assert_equal nil, res
  assert_equal [10,9,8,7,6,5,4,3,2,1], all
end

assert('break expression', '11.5.2.4.3') do
  assert_equal :result do
    while true
      break :result
    end
  end

  assert_equal :result do
    until false
      break :result
    end
  end
end

assert('next expression', '11.5.2.4.4') do
  assert_equal [8,6,4,2,0] do
    all = []
    idx = 10
    while idx > 0
      idx -= 1
      next if (idx % 2) == 1
      all << idx
    end
    all
  end

  assert_equal [8,6,4,2,0] do
    all = []
    idx = 10
    until idx == 0
      idx -= 1
      next if (idx % 2) == 1
      all << idx
    end
    all
  end
end
