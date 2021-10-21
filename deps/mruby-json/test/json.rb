assert('parse object') do
  assert_equal({"foo"=>"bar"}, JSON.parse('{"foo": "bar"}'))
end
assert('parse null') do
  assert_equal({"foo"=>nil}, JSON.parse('{"foo": null}'))
end
assert('parse array') do
  assert_equal "foo", JSON.parse('[true, "foo"]')[1] 
end
assert('parse multi-byte') do
  assert_equal({"あいうえお"=>"かきくけこ"}, JSON.parse('{"あいうえお": "かきくけこ"}'))
end
assert('parse object with numbers') do
  assert_equal({"latitude"=>33.6526,"longitude"=>177.96063}, JSON.parse('{"latitude": 33.6526,"longitude": 177.96063}'))
end
assert('stringify boolean') do
  assert_equal "true", JSON.stringify(true)
end
assert('stringify symbol') do
  assert_equal "\"symbol\"", JSON.stringify(:symbol)
end
assert('strnigify object with numeric value') do
  assert_equal '{"foo":"bar"}', JSON.stringify({"foo"=>"bar"})
end
assert('strnigify object with string value') do
  assert_equal '{"foo":1}', JSON.stringify({"foo"=> 1})
end
assert('stringify object with float value') do
  assert_equal '{"foo":2.5}', JSON.stringify({"foo"=> 2.5})
end
assert('stringify object with nil value') do
  assert_equal '{"foo":null}', JSON.stringify({"foo"=> nil})
end
assert('stringify object with boolean key and float value') do
  assert_equal '{"true":5}', JSON.stringify({true=> 5.0})
end
assert('stringify object with object key and float value') do
  assert_equal '{"{\"foo\"=>\"bar\"}":1.5}', JSON.stringify({{"foo"=> "bar"}=> 1.5})
end
assert('stringify empty array') do
  assert_equal "[]",  JSON.stringify([])
end
assert('strnigify array with few elements') do
  assert_equal "[1,true,\"foo\"]", JSON.stringify([1,true,"foo"]) 
end
assert('stringify object with several keys') do
  assert_equal '{"bar":2,"foo":1}', JSON.stringify({"bar"=> 2, "foo"=>1})
end
assert('stringify multi-byte') do
  assert_equal '{"foo":"ふー","bar":"ばー"}', JSON.stringify({"foo"=>"ふー", "bar"=> "ばー"})
end
assert('stringify escaped') do
  assert_equal '["\\\\"]', JSON.stringify(['\\'])
end
assert('stringify escaped quote') do
  assert_equal '["\\\\\\\\\""]', JSON.stringify(['\\\"'])
  s = JSON.stringify(['\\\"'])
  assert_equal '[', s[0]
  assert_equal '"', s[1]
  assert_equal '\\', s[2]; assert_equal '\\', s[3]
  assert_equal '\\', s[4]; assert_equal '\\', s[5]
  assert_equal '\\', s[6]; assert_equal '"', s[7]
  assert_equal '"', s[8]
  assert_equal ']', s[9]
end
assert('stringify object with to_json') do
  class Foo
    def to_json
      '{"foo":"foo"}'
    end
  end
  assert_equal '{"foo":"foo"}', JSON.stringify(Foo.new)
end
assert('stringify object with to_s') do
  class Bar
    def to_s
      "bar"
    end
  end
  assert_equal '"bar"', JSON.stringify(Bar.new)
end
assert('stringify object without to_s') do
  class Baz
  end
  s = JSON.stringify(Baz.new)
  assert_equal "\"#<Baz:", s[0,7]
end
assert('Hash#to_json') do
  assert_equal '{"foo":"bar"}', {"foo" => "bar"}.to_json
end
assert('String#to_json') do
  assert_equal '"foo"', "foo".to_json
end
assert('Fixnum#to_json') do
  assert_equal '1', 1.to_json
end
assert('TrueClass#to_json') do
  assert_equal 'true', true.to_json
end
assert('FalseClass#to_json') do
  assert_equal 'false', false.to_json
end
assert('Array#to_json') do
  assert_equal '[1,3,true,["foo"]]', [1 ,3, true,["foo"]].to_json
end
assert('Array#to_json') do
  assert_equal '[1,3,true,["foo"]]', [1 ,3, true,["foo"]].to_json
end
assert('pretty cat 🐱') do
  assert_equal "true", JSON.pretty_generate(true)
  assert_equal "1.2", JSON.pretty_generate(1.2)
  assert_equal "[\n]", JSON.pretty_generate([])
  assert_equal "{\n}", JSON.pretty_generate({})
  want =<<EOS
{
  "bar":[
    1,
    2,
    [
      {
        "baz":true
      },
      3
    ]
  ]
}
EOS
  assert_equal want[0..-2], JSON.pretty_generate({"bar"=> [1,2,[{"baz" => true}, 3]]})
end
assert('dump') do
  class DummyWriter
    def initialize();@s = '';end
    def write(s);@s += s;end
    def to_s();@s;end
  end
  w = DummyWriter.new
  JSON.dump(123, w)
  assert_equal "123", w.to_s
end
assert('ParserError') do
  assert_raise(JSON::ParserError) { JSON.parse('{') }
end
assert('load') do
  assert_equal({"foo"=>"bar"}, JSON.load('{"foo": "bar"}'))

  o = nil
  JSON.load '{"foo": "bar"}' do |x| o = x; end
  assert_equal({"foo"=>"bar"}, o)

  o = nil
  assert_raise(JSON::ParserError) { JSON.load '{' {|x| o = x} }
  assert_equal(nil, o)
end
