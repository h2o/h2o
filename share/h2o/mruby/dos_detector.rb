# Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
require File.expand_path(File.dirname(__FILE__)) + "/lru_cache.rb"

class DoSDetector

  def initialize(config={})
    config = {
      :strategy   => CountingStrategy.new,
      :callback   => self.class.default_callback,
      :forwarded  => true,
      :cache_size => 128,
    }.merge(config)

    @strategy = config[:strategy]
    @callback = config[:callback]
    @forwarded = !!(config[:forwarded])
    @cache = LRUCache.new(config[:cache_size])
    raise "strategy must not be nil" if @strategy.nil?
    raise "callback must not be nil" if @callback.nil?
  end

  def self.default_callback
    Proc.new do |env, detected, ip|
      if detected
        [ 403, { "Content-Type" => "text/plain" }, [ "Forbidden" ] ]
      else
        [ 399, {}, [] ]
      end
    end
  end

  def self.fallthrough_callback
    Proc.new do |env, detected, ip, vars|
      if detected
        vars ||= {}
        env_headers = vars.merge({:ip => ip}).map { |k, v| [ "x-fallthru-set-dos-#{k}", v.to_s ] }.to_h
        [ 399, env_headers, [] ]
      else
        [ 399, {}, [] ]
      end
    end
  end

  def call(env)
    now = Time.now.to_i

    ip = env['REMOTE_ADDR']
    if @forwarded && (xff = env['HTTP_X_FORWARDED_FOR'])
      ip = xff.split(",")[0]
    end

    unless client = @cache.get(ip)
      client = { :ip => ip }
      @cache.set(ip, client)
    end

    detected, *args = @strategy.detect?(client, now, env)
    return @callback.call(env, detected, ip, *args)
  end

  class CountingStrategy

    def initialize(config={})
      config = {
        :period     => 10,
        :threshold  => 100,
        :ban_period => 300,
      }.merge(config)
      @period = config[:period]
      @threshold = config[:threshold]
      @ban_period = config[:ban_period]
      raise "period must be greater than zero" if @period <= 0
      raise "threshold must be greater than zero" if @threshold <= 0
      raise "ban_period must not be negative" if @ban_period < 0
    end

    def detect?(client, now, env)
      count = countup(client, now)

      banned_until = client[:banned_until] || 0
      if banned_until >= now
        detected = true
      else
        detected = count >= @threshold 
        if detected
          banned_until = now + @ban_period
          client[:banned_until] = banned_until
        end
      end

      return detected, { :count => count, :banned_until => banned_until }
    end

    private

    def countup(client, now)
      count = client[:count] || 0
      period_index = client[:period_index] || 0

      current_period_index = (now / @period).floor
      if current_period_index > period_index
        count -= (current_period_index - period_index) * @threshold
        count = 0 if count < 0
        client[:period_index] = current_period_index
      end

      count += 1
      client[:count] = count

      return count
    end

  end

end
