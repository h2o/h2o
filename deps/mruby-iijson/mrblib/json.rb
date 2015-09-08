module JSON
  def self.dump(object, io=nil, limit=nil)
    state = {}
    state[:max_nesting] = limit if limit
    begin
      js = JSON.generate(object, nil, state)
    rescue JSON::NestingError
      raise ArgumentError, "exceeded depth limit"
    end
    if io
      io.write js
      io
    else
      js
    end
  end

  def self.generate(obj, options=nil, state=nil)
    options = (options || {}).to_hash unless options.is_a? Hash
    options[:pretty_print] ||= false
    options[:indent_with] ||= 2
    state = (state || {}).to_hash unless state.is_a? Hash
    state[:max_nesting] ||= 100
    state[:nesting] = 0
    self.generate0(obj, options, state)
  end

  def self.generate0(obj, options, state)
    if state[:nesting] >= state[:max_nesting]
      raise JSON::NestingError, "nesting of #{state[:nesting]} is too deep"
    end

    pretty = options[:pretty_print]
    
    if pretty
      indent = options[:indent_with].class == Fixnum ? " " * options[:indent_with] : options[:indent_with]
    else
      indent = ""
    end

    nl = pretty ? "\n" : ""

    if obj == false
      return "false"

    elsif obj == nil
      return "null"

    elsif obj == true
      return "true"

    elsif obj.is_a? Hash
      members = []
      state[:nesting] += 1
      obj.each { |k, v|
        members << JSON.generate0(k, options, state) + ":" + (pretty ? " " : "") + JSON.generate0(v, options, state)
      }
      if pretty
        members.map! { |k| (indent * state[:nesting]) + "#{k}" }.join("_")
      end
      state[:nesting] -= 1
      return "{" + nl + members.join("," + nl) + nl + (indent * state[:nesting]) + "}"

    elsif obj.is_a? Array
      state[:nesting] += 1
      members = obj.map { |v| JSON.generate0(v, options, state) }
      if pretty
        members.map! { |k| (indent * state[:nesting]) + "#{k}" }.join("_")
      end
      state[:nesting] -= 1
      return "[" + nl + members.join("," + nl) + nl + (indent * state[:nesting]) + "]"

    elsif obj.is_a? Fixnum
      return obj.to_s

    elsif obj.is_a? Float
      if obj.infinite? or obj.nan?
        raise GeneratorError, "#{obj.to_s} not allowed in JSON"
      end
      sprintf "%.17g", obj

    else
      a = []
      obj.to_s.each_char { |ch|
        a << if ch < "\x20"
          case ch 
          when "\x08"
            "\\b"
          when "\x0c"
            "\\f"
          when "\x0a"
            "\\n"
          when "\x0d"
            "\\r"
          when "\x09"
            "\\t"
          else
            raise GeneratorError, "cannot convert #{ch.inspect} to JSON"
          end
        elsif ch == '"'
          '\\"'
        elsif ch == '\\'
          "\\\\"
        else
          ch
        end
      }
      return '"' + a.join + '"'
    end
  end

  def self.load(source)  # TODO: proc, options
    source = source.read unless source.is_a? String
    JSON.parse source
  end
  
  class JSONError < StandardError; end
  class GeneratorError < JSONError; end
  class ParserError < JSONError; end
  class NestingError < ParserError; end
end

unless Float.method_defined? :nan?
  class Float
    def nan?
      not (self == self)
    end
  end
end
