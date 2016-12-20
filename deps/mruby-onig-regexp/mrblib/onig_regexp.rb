class OnigRegexp
  @memo = {}

  # ISO 15.2.15.6.1
  def self.compile(*args)
    as = args.to_s
    unless @memo.key? as
      @memo[as] = self.new(*args)
    end
    @memo[as]
  end

  # ISO 15.2.15.6.3
  def self.last_match
    @last_match
  end

  # ISO 15.2.15.7.2
  def initialize_copy(other)
    initialize(other.source, other.options)
  end

  # ISO 15.2.15.7.4
  def ===(str)
    not self.match(str).nil?
  end

  # ISO 15.2.15.7.5
  def =~(str)
    m = self.match(str)
    m ? m.begin(0) : nil
  end

  # ISO 15.2.15.7.8
  attr_reader :source
end

class String
  # ISO 15.2.10.5.5
  def =~(a)
    begin
      (a.class.to_s == 'String' ?  Regexp.new(a.to_s) : a) =~ self
    rescue
      false
    end
  end

  # redefine methods with oniguruma regexp version
  [:sub, :gsub, :split, :scan].each do |v|
    alias_method "string_#{v}".to_sym, v
    alias_method v, "onig_regexp_#{v}".to_sym
  end

  alias_method :old_slice, :slice
  alias_method :old_square_brancket, :[]

  def [](*args)
    return old_square_brancket(*args) unless args[0].class == Regexp

    if args.size == 2
      match = args[0].match(self)
      if match
        if args[1] == 0
          str = match[0]
        else
          str = match.captures[args[1] - 1]
        end
        return str
      end
    end

    match_data = args[0].match(self)
    if match_data
      result = match_data.to_s
      return result
    end
  end

  alias_method :slice, :[]

  def slice!(*args)
    if args.size < 2
      result = slice(*args)
      nth = args[0]

      if nth.class == Regexp
        lm = Regexp.last_match
        self[nth] = '' if result
        Regexp.last_match = lm
      else
        self[nth] = '' if result
      end
    else
      result = slice(*args)

      nth = args[0]
      len = args[1]

      if nth.class == Regexp
        lm = Regexp.last_match
        self[nth, len] = '' if result
        Regexp.last_match = lm
      else
        self[nth, len] = '' if result && nth != self.size
      end
    end

    result
  end

  alias_method :old_index, :index

  def index(pattern, pos=0)
    if pattern.class == Regexp
      str = self[pos..-1]
      if str
        if num = (pattern =~ str)
          if pos < 0
            num += self.size
          end
          return num + pos
        end
      end
      nil
    else
      self.old_index(pattern, pos)
    end
  end
end

module Kernel
  def =~(_)
    nil
  end
end

Regexp = OnigRegexp unless Object.const_defined?(:Regexp)
MatchData = OnigMatchData unless Object.const_defined? :MatchData

# This is based on https://github.com/masamitsu-murase/mruby-hs-regexp
