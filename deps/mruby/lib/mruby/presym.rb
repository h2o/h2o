module MRuby
  class Presym
    OPERATORS = {
      "!" => "not",
      "%" => "mod",
      "&" => "and",
      "*" => "mul",
      "+" => "add",
      "-" => "sub",
      "/" => "div",
      "<" => "lt",
      ">" => "gt",
      "^" => "xor",
      "`" => "tick",
      "|" => "or",
      "~" => "neg",
      "!=" => "neq",
      "!~" => "nmatch",
      "&&" => "andand",
      "**" => "pow",
      "+@" => "plus",
      "-@" => "minus",
      "<<" => "lshift",
      "<=" => "le",
      "==" => "eq",
      "=~" => "match",
      ">=" => "ge",
      ">>" => "rshift",
      "[]" => "aref",
      "||" => "oror",
      "<=>" => "cmp",
      "===" => "eqq",
      "[]=" => "aset",
    }.freeze

    SYMBOL_TO_MACRO = {
    #      Symbol      =>      Macro
    # [prefix, suffix] => [prefix, suffix]
      ["@@"  , ""    ] => ["CV"  , ""    ],
      ["@"   , ""    ] => ["IV"  , ""    ],
      [""    , "!"   ] => [""    , "_B"  ],
      [""    , "?"   ] => [""    , "_Q"  ],
      [""    , "="   ] => [""    , "_E"  ],
      [""    , ""    ] => [""    , ""    ],
    }.freeze

    C_STR_LITERAL_RE = /"(?:[^\\\"]|\\.)*"/

    def initialize(build)
      @build = build
    end

    def scan(paths)
      presym_hash = {}
      paths.each {|path| read_preprocessed(presym_hash, path)}
      presym_hash.keys.sort_by!{|sym| [c_literal_size(sym), sym]}
    end

    def read_list
      File.readlines(list_path, mode: "r:binary").each(&:chomp!)
    end

    def write_list(presyms)
      _pp "GEN", list_path.relative_path
      File.binwrite(list_path, presyms.join("\n") << "\n")
    end

    def write_id_header(presyms)
      prefix_re = Regexp.union(*SYMBOL_TO_MACRO.keys.map(&:first).uniq)
      suffix_re = Regexp.union(*SYMBOL_TO_MACRO.keys.map(&:last).uniq)
      sym_re = /\A(#{prefix_re})?([\w&&\D]\w*)(#{suffix_re})?\z/o
      _pp "GEN", id_header_path.relative_path
      File.open(id_header_path, "w:binary") do |f|
        f.puts "enum mruby_presym {"
        presyms.each.with_index(1) do |sym, num|
          if sym_re =~ sym && (affixes = SYMBOL_TO_MACRO[[$1, $3]])
            f.puts "  MRB_#{affixes * 'SYM'}__#{$2} = #{num},"
          elsif name = OPERATORS[sym]
            f.puts "  MRB_OPSYM__#{name} = #{num},"
          end
        end
        f.puts "};"
        f.puts
        f.puts "#define MRB_PRESYM_MAX #{presyms.size}"
      end
    end

    def write_table_header(presyms)
      _pp "GEN", table_header_path.relative_path
      File.open(table_header_path, "w:binary") do |f|
        f.puts "static const uint16_t presym_length_table[] = {"
        presyms.each{|sym| f.puts "  #{sym.bytesize},\t/* #{sym} */"}
        f.puts "};"
        f.puts
        f.puts "static const char * const presym_name_table[] = {"
        presyms.each{|sym| f.puts %|  "#{sym}",|}
        f.puts "};"
      end
    end

    def list_path
      @list_path ||= "#{@build.build_dir}/presym".freeze
    end

    def header_dir;
      @header_dir ||= "#{@build.build_dir}/include/mruby/presym".freeze
    end

    def id_header_path
      @id_header_path ||= "#{header_dir}/id.h".freeze
    end

    def table_header_path
      @table_header_path ||= "#{header_dir}/table.h".freeze
    end

    private

    def read_preprocessed(presym_hash, path)
      File.binread(path).scan(/<@! (.*?) !@>/) do |part,|
        literals = part.scan(C_STR_LITERAL_RE)
        presym_hash[literals.map{|l| l[1..-2]}.join] = true unless literals.empty?
      end
    end

    def c_literal_size(literal_without_quote)
      literal_without_quote.size  # TODO: consider escape sequence
    end
  end
end
