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

module H2O
  class Prometheus

    @@gauge_types = ['uptime', 'connections', 'num-sessions', 'evloop-latency-nanosec']

    def initialize(app)
      @app = app
    end

    def type_for(key)
      if @@gauge_types.include?(key) then
        'gauge'
      elsif key =~ /-[0-9]+\z/ then
        'gauge'
      else
        'counter'
      end
    end

    def call(env)
      env['PATH_INFO'] = '/json'
      status, headers, body = @app.call(env)
      stats = JSON.parse(body.join)
      version = stats.delete('server-version') || ''
      stats = stats.select {|k, v| v.kind_of?(Numeric) || v.kind_of?(Array) }
      s = ""
      stats.each {|k, v|
        v = 0 if v.nil?

        type = type_for(k)

        # sanitize invalid characters to underscore
        pk = "h2o_#{k.gsub(/[^a-zA-Z0-9:_]/, '_')}";

        s += "# HELP #{pk} #{k}\n"
        s += "# TYPE #{pk} #{type}\n" if type

        if k == 'evloop-latency-nanosec' then
          v.each_with_index do |vv, i|
            s += "#{pk}{version=\"#{version}\", thread=\"#{i}\"} #{vv}\n"
          end
        else
          s += "#{pk}{version=\"#{version}\"} #{v}\n"
        end
      }
      [status, headers, [s]]
    end

  end
end
