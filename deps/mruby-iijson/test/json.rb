assert('JSON.dump') do
  class JsonTestIo
    def initialize
      @buf = ""
    end
    def write(str)
      @buf += str
    end
    attr_reader :buf
  end
  assert_equal "[1]", JSON.dump([1])

  jio = JsonTestIo.new
  JSON.dump(["abc"], jio)
  assert_equal '["abc"]', jio.buf

  assert_raise(ArgumentError) do
    JSON.dump({:a => {:b => {} } }, nil, 2)
  end
  JSON.dump({:a=>{:b=>{}}}, nil, 3)  # should not raise
end

assert('JSON.generate: false') do
  assert_equal "false", JSON.generate(false)
end

assert('JSON.generate: null') do
  assert_equal "null", JSON.generate(nil)
end

assert('JSON.generate: true') do
  assert_equal "true", JSON.generate(true)
end

assert('JSON.generate: object') do
  assert_equal '{"key":"value"}', JSON.generate({ "key" => "value" })
  assert_equal '{"ten":10}', JSON.generate({ :ten => 10 })
end

assert('JSON.generate: array') do
  assert_equal '[null,1,"two"]', JSON.generate([ nil, 1, "two"])
end

assert('JSON.generate: number (Fixnum)') do
  str = JSON.generate [1]
  assert_equal "[1]", str
end

assert('JSON.generate: number (Float)') do
  str = JSON.generate [134.625]
  assert_equal "[134.625]", str
end

assert('JSON.generate: string') do
  assert_equal "\"abc\"", JSON.generate("abc")
  assert_equal "\"\\\"\\\\/\\b\\f\\n\\r\\t\"",
    JSON.generate("\x22\x5c\x2f\x08\x0c\x0a\x0d\x09")
end

assert('JSON.load') do
  assert_equal [1,2,3], JSON.load("[1,2,3]")

  class JsonTestReader
    def read
      '{"abc":123}'
    end
  end
  assert_equal({"abc"=>123}, JSON.load(JsonTestReader.new))
end

assert('JSON.parse: text from RFC4726') do
  str = '{
    "Image": {
      "Width":  800,
      "Height": 600,
      "Title":  "View from 15th Floor",
      "Thumbnail": {
        "Url":    "http://www.example.com/image/481989943",
        "Height": 125,
        "Width":  "100"
      },
      "IDs": [116, 943, 234, 38793]
    }
  }'
  hash = {
    "Image" => {
      "Width" => 800,
      "Height" => 600,
      "Title" => "View from 15th Floor",
      "Thumbnail" => {
        "Url" => "http://www.example.com/image/481989943",
        "Height" => 125,
        "Width" => "100"
      },
      "IDs" => [116, 943, 234, 38793]
    }
  }
  assert_equal hash, JSON.parse(str)

  # We cannot compare `str` with `JSON.generate(hash)` because Hash entries
  # will be in a random order.
  assert_equal hash, JSON.parse(JSON.generate(hash))
end

assert('JSON::ParserError') do
  assert_raise(JSON::ParserError) do
    JSON.parse "[xxx]"
  end
end

assert('JSON.parse: empty string is not a valid JSON text') do
  assert_raise(JSON::ParserError) do
    JSON.parse ""
  end
end

assert('#to_json') do
  assert_equal 'false',     false.to_json
  assert_equal 'null',      nil.to_json
  assert_equal 'true',      true.to_json
  assert_equal '1',         1.to_json
  assert_equal '3.125',      3.125.to_json
  assert_equal '"str"',     "str".to_json
  assert_equal '["one",2]', [ "one", 2 ].to_json
  assert_equal '{"a":1}',   { "a" => 1 }.to_json
end
