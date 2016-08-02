require "lru_cache.rb"

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
    Proc.new do |vars|
      [ 403, { "Content-Type" => "text/plain" }, [ "Forbidden" ] ]
    end
  end

  def self.fallthrough_callback
    Proc.new do |vars|
      env_headers = vars.map { |k, v| [ "x-fallthru-set-dos-#{k}", v.to_s ] }.to_h
      [ 399, env_headers, [] ]
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

    detected, vars = @strategy.detect?(client, now, env)
    if detected
      vars = { :ip => client[:ip] }.merge(vars || {})
      return @callback.call(vars)
    end
    return [ 399, {}, [] ]
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
