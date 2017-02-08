class LoadError < ScriptError; end

begin
  eval "1", nil
  def _require_eval_load(*args)
    self.eval(*args)
  end
rescue ArgumentError
  def _require_eval_load(*args)
    self.eval(args[0])
  end
end

module Kernel
  def load(path)
    raise TypeError unless path.class == String

    if File.exist?(path) && File.extname(path) == ".mrb"
      _load_mrb_file path
    elsif File.exist?(path)
      # _load_rb_str File.open(path).read.to_s, path
      _require_eval_load File.open(path).read.to_s, nil, path
    else
      raise LoadError.new "File not found -- #{path}"
    end

    true
  end

  def require(path)
    raise TypeError unless path.class == String

    # require method can load .rb, .mrb or without-ext filename only.
    unless ["", ".rb", ".mrb"].include? File.extname(path)
      raise LoadError.new "cannot load such file -- #{path}"
    end

    filenames = []
    if File.extname(path).size == 0
      filenames << "#{path}.rb"
      filenames << "#{path}.mrb"
    else
      filenames << path
    end

    dir = nil
    filename = nil
    if ['/', '.'].include? path[0]
      path0 = filenames.find do |fname|
        File.file?(fname) && File.exist?(fname)
      end
    else
      dir = ($LOAD_PATH || []).find do |dir0|
        filename = filenames.find do |fname|
          path0 = File.join dir0, fname
          File.file?(path0) && File.exist?(path0)
        end
      end
      path0 = dir && filename ? File.join(dir, filename) : nil
    end

    if path0 && File.exist?(path0) && File.file?(path0)
      __require__ path0
    else
      raise LoadError.new "cannot load such file -- #{path}"
    end
  end

  def __require__(realpath)
    raise LoadError.new "File not found -- #{realpath}"  unless File.exist? realpath
    $" ||= []
    $__mruby_loading_files__ ||= []

    # already required
    return false  if ($" + $__mruby_loading_files__).include?(realpath)

    $__mruby_loading_files__ << realpath
    load realpath
    $" << realpath
    $__mruby_loading_files__.delete realpath

    true
  end
end


$LOAD_PATH ||= []
$LOAD_PATH << '.'

if Object.const_defined?(:ENV)
  $LOAD_PATH.unshift(*ENV['MRBLIB'].split(':')) unless ENV['MRBLIB'].nil?
end

$LOAD_PATH.uniq!

$" ||= []
$__mruby_loading_files__ ||= []
