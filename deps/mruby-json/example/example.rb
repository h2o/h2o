#!mruby

puts JSON::parse('{"foo": "bar"}') == {"foo"=>"bar"}
puts JSON::parse('{"foo": null}') == {"foo"=>nil}
puts JSON::parse('[true, "foo"]')[1] == "foo"
puts JSON::stringify(true) == "true"
puts JSON::stringify({"foo"=>"bar"}) == '{"foo":"bar"}'
puts JSON::stringify({"foo"=> 1}) == '{"foo":1}'
puts JSON::stringify({"foo"=> 2.3}) == '{"foo":2.3}'
puts JSON::stringify({"foo"=> nil}) == '{"foo":null}'
puts JSON::stringify({true=> 3.4}) == '{"true":3.4}'
puts JSON::stringify({{"foo"=> "bar"}=> 1.2}) == '{"{\"foo\"=>\"bar\"}":1.2}'
puts JSON::stringify([]) == "[]"
puts JSON::stringify([1,true,"foo"]) == "[1,true,\"foo\"]"
