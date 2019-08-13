#!mruby

class Foo
  def greeting(*args)
    puts "Hey #{args[0]}!"
    "hello #{args[0]}!"
  end
end

h = HTTP::Parser.new()
s = UV::TCP.new()
s.bind(UV::ip4_addr('127.0.0.1', 8888))
s.listen(1024) {|x|
  return if x != 0
  c = s.accept()
  c.read_start {|b|
    return unless b
    h.parse_request(b) {|r|
      if r.method == 'POST'
        begin
          rpc = JSON::parse(r.body)
          ret = nil
          if rpc.key?("method") && rpc['method'] == 'Foo.greeting'
            params = rpc['params']
            params = params.values if params.class.to_s == 'Hash'
            params = [params] if params.class.to_s != 'Array'
            params = [nil] if params.size == 0
            ret = Foo.new.send('greeting', params[0])
          else
            ret = {"error"=> "unknown method"}
          end
        rescue ArgumentError => e
          ret = {"error"=> e.to_s}
        end
        c.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n#{JSON::stringify(ret)}") {|x|
          c.close() if c
          c = nil
        }
      else
        c.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello world") {|x|
          c.close() if c
          c = nil
        }
      end
    }
  }
}

t = UV::Timer.new
t.start(5000, 5000) {|x|
  UV::gc()
  GC.start
}

UV::run()
