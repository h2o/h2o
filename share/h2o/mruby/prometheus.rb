# Copyright (c) 2018 Fastly, Frederik Deweerdt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

class Prometheus

    def initialize(app)
      @app = app
    end

    def call(env)
        env['PATH_INFO'] = '/json'
        status, headers, body = @app.call(env)
        stats = JSON.parse(body.join)
        s = ""
        version = ""
        keys = {}
        stats.each { |k,v|
            next if v.kind_of?(Array)
            next if k =~ "-time$"
            if k == "server-version" then
                version = v 
                next
            end
            keys[k] = v
        }
        keys.each { |k,v|
            next if k =~ "-type$"

            type = keys["#{k}-type"]
            type = "counter" unless type

            s += "#HELP #{k}\n"
            s += "#TYPE #{k} #{type}\n"
            s += "#{k}{version=\"#{version}\"} #{v}\n"
        }
        [status, headers, [s]]
    end
end
