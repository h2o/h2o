# mruby-iijson

"mruby-iijson" is JSON module for mruby.


## Implemented Methods:
 - [JSON.dump](http://docs.ruby-lang.org/en/2.2.0/JSON.html#method-i-dump)
 - [JSON.generate](http://docs.ruby-lang.org/en/2.2.0/JSON.html#method-i-generate)
 - [JSON.load](http://docs.ruby-lang.org/en/2.2.0/JSON.html#method-i-load)
 - [JSON.parse](http://docs.ruby-lang.org/en/2.2.0/JSON.html#method-i-parse)
 - `Array#to_json`, `Fixnum#to_json`, `Float#to_json`, `Hash#to_json`, `String#to_json`, ...

## Example:

```Ruby
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
p JSON.parse(str)

h = {
  :precision => "zip",
  :Latitude  =>  37.7668,
  :Longitude => -122.3959,
  :Address   => "",
  :City      => "SAN FRANCISCO",
  :State     => "CA",
  :Zip       => "94107",
  :Country   => "US"
}
p h.to_json
puts JSON.generate(h, {:pretty_print => true, :indent_with => 2})
```

```
{"Image"=>{"Width"=>800, "Height"=>600, "Title"=>"View from 15th Floor", "Thumbnail"=>{"Url"=>"http://www.example.com/image/481989943", "Height"=>125, "Width"=>"100"}, "IDs"=>[116, 943, 234, 38793]}}
"{\"precision\":\"zip\",\"Latitude\":37.766800000000003,\"Longitude\":-122.3959,\"Address\":\"\",\"City\":\"SAN FRANCISCO\",\"State\":\"CA\",\"Zip\":\"94107\",\"Country\":\"US\"}"
{
  "precision": "zip",
  "Latitude": 37.766800000000003,
  "Longitude": -122.3959,
  "Address": "",
  "City": "SAN FRANCISCO",
  "State": "CA",
  "Zip": "94107",
  "Country": "US"
}
```


## Caveats

 - JSON.generate won't return if input Array/Hash has circular reference.


## License

Copyright (c) 2014 Internet Initiative Japan Inc.

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
