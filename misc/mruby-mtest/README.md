Minimum Test Framework for mruby
=========

[![Build Status](https://travis-ci.org/iij/mruby-mtest.svg?branch=master)](https://travis-ci.org/iij/mruby-mtest)

## example
```ruby
class Test4MTest < MTest::Unit::TestCase
  def test_assert
    assert(true)
    assert(true, 'true sample test')
  end
end

MTest::Unit.new.run
```

### How to use mrbgem's mrbtest
```ruby
if Object.const_defined?(:MTest)
  class Test4MTest < MTest::Unit::TestCase
    def test_assert_nil
      assert_nil(nil, 'nil sample test')
    end
  end

  if $ok_test
    MTest::Unit.new.mrbtest
  else
    MTest::Unit.new.run
  end
else
  $asserts << "test skip of Test4MTest."  if $asserts
end
```

## TODO

 - MiniTest::Unit.autorun is not implemented (because mruby hasn't ``at_exit`` method.)


## License

Copyright (c) 2013 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.

