class MRBDoc
  SRC_DIR = 'src'
  MRBLIB_DIR = 'mrblib'

  def analyze_code dir, &block
    @mrb_files = {}
    @dir = File.expand_path(dir)

    block.call "MRBDOC\tanalyze #{@dir}"

    analyze(dir) do |progress|
      block.call progress
    end
  end

  def each_file(&block); @mrb_files.each {|k,v| block.call k,v}; end

  def find_c_func(c_func_name)
    each_file do |file_name, file|
      c_func = file.c_funcs(c_func_name)
      return c_func unless c_func.nil?
    end
    {}
  end

  def find_c_file(rb_obj_name, c_func_name)
    last_file_name_match = ''
    each_file do |file_name, file|
      c_func = file.c_funcs(c_func_name)
      if c_func and file.rb_class(rb_obj_name) or file.rb_module(rb_obj_name)
        return file_name
      elsif c_func
        last_file_name_match = file_name
      end
    end
    last_file_name_match
  end

  def find_c_file_by_class(name)
    each_file do |file_name, file|
      rb_class = file.rb_class(name)
      return file_name unless rb_class.nil?
    end
    'nil'
  end

  def find_c_file_by_module(name)
    each_file do |file_name, file|
      rb_module = file.rb_module(name)
      return file_name unless rb_module.nil?
    end
    'nil'
  end

  private

  def analyze dir, &block
    collect_all_files dir, &block
  end

  def collect_all_files dir, &block
    l = lambda {|f| block.call "  - #{f.name}"}
    collect_files(src_code_dir(dir), /\.c$/, &l)
    collect_files(mrb_code_dir(dir), /\.rb$/, &l)
  end

  def collect_files dir, rxp, &block
    Dir.foreach(dir) do |file|
      next unless file =~ rxp

      file_path = "#{dir}/#{file}"
      mrb_file = MRBFile.new "#{file_path}"
      @mrb_files["#{file_path}"] = mrb_file

      block.call mrb_file
    end
  end

  def src_code_dir dir; File.expand_path SRC_DIR, dir; end
  def mrb_code_dir dir; File.expand_path MRBLIB_DIR, dir; end
end

class MRBFile
  attr_reader :name
  attr_reader :file

  def initialize mrb_file
    @file = mrb_file
    @name = File.basename file
    @c_funcs = {}
    @rb_class_c_def = {}
    @rb_method_c_def = {}
    @rb_class_method_c_def = {}
    @rb_module_c_def = {}
    @last_line = nil
    @assignments = {}

    @assignments['mrb->object_class'] = 'Object'
    @assignments['mrb->kernel_module'] = 'Kernel'
    @assignments['mrb->module_class'] = 'Module'
    @assignments['mrb->nil_class'] = 'NilClass'
    @assignments['mrb->true_class'] = 'TrueClass'
    @assignments['mrb->class_class'] = 'Class'

    analyze
  end

  def each_class &block
    @rb_class_c_def.each do |class_name, class_hsh|
      block.call class_name, class_hsh
    end
  end

  def each_method name, &block
    @rb_method_c_def.each do |met_name, met_hsh|
      met_name_tmp = met_name.sub /^#{name}_/, ''
      block.call met_name_tmp, met_hsh if met_hsh[:rb_class] == name
    end
  end

  def each_class_method name, &block
    @rb_class_method_c_def.each do |met_name, met_hsh|
      met_name_tmp = met_name.sub /^#{name}_/, ''
      block.call met_name_tmp, met_hsh if met_hsh[:rb_class] == name
    end
  end

  def each_module &block
    @rb_module_c_def.each do |module_name, module_hsh|
      block.call module_name, module_hsh
    end
  end

  def each_core_object &block
    each_class {|n| block.call n}
    each_module {|n| block.call n}
  end

  def c_funcs c_func_name; @c_funcs[c_func_name]; end
  def rb_class rb_class_name; @rb_class_c_def[rb_class_name]; end
  def rb_module rb_module_name; @rb_module_c_def[rb_module_name]; end

  private

  def analyze
    File.open(file).each_line.each_with_index do |line, idx|
      line_no = idx.succ
      if c_file?
        analyze_c_line line, line_no
      elsif rb_file?
        analyze_rb_line line, line_no
      else
        raise ArgumentError.new "#{file} is a not supported file type"
      end
      @last_line = line.strip
    end
  end

  def c_file?; (name =~ /\.c$/); end
  def rb_file?; (name =~ /\.rb$/); end

  RXP_C_VAR = /\s*([^\s]*?)\s*?/
  RXP_C_STR = /\s*?\"(.*?)\"\s*?/
  #RXP_C_ISO = /\s*\;\s*[\/\*]*\s*.*?([15\.]{0,3}[0-9\.]*)\s*[\\\\\*]*/
  RXP_C_ISO = /\s*;\s*[\/\*]*[\sa-zA-Z]*([\d\.]*)[\sa-zA-Z]*[\*\/]*/

  def analyze_c_line line, line_no
    case line.strip
    when /^([a-zA-Z\_][a-zA-Z\_0-9]*?)\((.*?)\)\s*?$/
      # assuming c method definition
      @c_funcs[$1] = {:line_no => line_no, :args => $2, :return => @last_line}
    when /mrb_define_class\(.*?\,#{RXP_C_STR}\,#{RXP_C_VAR}\)#{RXP_C_ISO}/
      # assuming ruby class definition in c
      class_name = $1.clone
      iso = $3.clone
      iso.strip!
      @rb_class_c_def[class_name] = {:c_object => $2, :iso => iso}
      assigns = line.split '='
      if assigns.size > 1
        assigns[0..-2].each do |v|
          @assignments[v.strip] = class_name
        end
      end
    when /mrb_define_module\(.*?\,#{RXP_C_STR}\)#{RXP_C_ISO}/
      # assuming ruby class definition in c
      module_name = $1.clone
      iso = $2.clone
      iso.strip!
      @rb_module_c_def[module_name] = {:iso => iso}
      assigns = line.split '='
      if assigns.size > 1
        assigns[0..-2].each do |v|
          @assignments[v.strip] = module_name
        end
      end
    when /mrb_define_method\(.*?\,#{RXP_C_VAR}\,#{RXP_C_STR}\,#{RXP_C_VAR}\,#{RXP_C_VAR}\)#{RXP_C_ISO}/
      # assuming ruby method definition in c
      name = $1.clone
      name = resolve_obj(name)
      iso = $5.clone
      iso.strip!
      @rb_method_c_def["#{name}_#{$2}"] = {:c_func => $3, :args => $4, :rb_class => name, :iso => iso}
    when /mrb_define_class_method\(.*?\,#{RXP_C_VAR}\,#{RXP_C_STR}\,#{RXP_C_VAR}\,#{RXP_C_VAR}\)#{RXP_C_ISO}/
      # assuming ruby class method definition in c
      class_name = $1.clone
      class_name = resolve_obj(class_name)
      iso = $5.clone
      iso.strip!
      @rb_class_method_c_def["#{class_name}_#{$2}"] = {:c_func => $3, :args => $4, :rb_class => class_name, :iso => iso}
    when /mrb_name_class\(.*?\,#{RXP_C_VAR}\,\s*mrb_intern\(.*?,#{RXP_C_STR}\)\)#{RXP_C_ISO}/
      class_name = $2.clone
      iso = $3.clone
      iso.strip!
      @rb_class_c_def[class_name] = {:c_object => $1, :iso => iso}
      @assignments[$1] = class_name
    when /mrb_include_module\(.*?\,#{RXP_C_VAR}\,\s*mrb_class_get\(.*?\,#{RXP_C_STR}\)\)/
      class_name = resolve_obj($1)
      mod = $2.clone
      @rb_class_c_def[class_name][:include] = [] unless @rb_class_c_def[class_name].has_key? :include
      @rb_class_c_def[class_name][:include] << mod
    end
  end

  def analyze_rb_line line, line_no

  end

  def resolve_obj c_var
    @assignments[c_var]
  end
end
