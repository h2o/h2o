module MRuby
  BENCHMARK_REPEAT = 4
end

$dat_files = []

def bm_files
  Dir.glob("#{MRUBY_ROOT}/benchmark/bm_*.rb")
end

def build_config_name
  if ENV['MRUBY_CONFIG']
    File.basename(ENV['MRUBY_CONFIG'], '.rb').gsub('build_config_', '')
  else
    "build"
  end
end

def plot_file
  File.join(MRUBY_ROOT, 'benchmark', "#{build_config_name}.png")
end

def plot
  opts_file = "#{MRUBY_ROOT}/benchmark/plot.gpl"
  opts = File.read(opts_file).each_line.to_a.map(&:strip).join(';')

  dat_files = $dat_files.group_by {|f| File.dirname(f).split(File::SEPARATOR)[-1]}

  opts += ";set output '#{plot_file}'"

  opts += ';plot '

  opts += dat_files.keys.map do |data_file|
    %Q['-' u 2:3:4:xtic(1) w hist title columnheader(1)]
  end.join(',')
  opts += ';'

  cmd = %Q{gnuplot -p -e "#{opts}"}

  IO.popen(cmd, 'w') do |p|
    dat_files.each do |target_name, bm_files|
      p.puts target_name.gsub('_', '-')
      bm_files.each do |bm_file|
        p.write File.read(bm_file)
      end
      p.puts "e"
    end
  end
end


MRuby.each_target do |target|
  next if target.name == 'host'
  mruby_bin = "#{target.build_dir}/bin/mruby"

  bm_files.each do |bm_file|
    bm_name = File.basename bm_file, ".rb"

    dat_dir = File.join('benchmark', build_config_name, target.name)
    dat_file = File.join(dat_dir, "#{bm_name}.dat")
    $dat_files << dat_file

    directory dat_dir

    file dat_file => [bm_file, dat_dir, mruby_bin] do |task|
      print bm_name
      puts "..."

      data = (0...MRuby::BENCHMARK_REPEAT).map do |n|
        str = %x{(time -f "%e %S %U" #{mruby_bin} #{bm_file}) 2>&1 >/dev/null}
        str.split(' ').map(&:to_f)
      end

      File.open(task.name, "w") do |f|
        data = data.map {|_,r,s| (r + s) / 2.0}
        min = data.min
        max = data.max
        avg = data.inject(&:+) / data.size
        f.puts "#{bm_name.gsub('_', '-')} #{avg} #{min} #{max}"
      end
    end
  end
end

file plot_file => $dat_files do
  plot
end

task :benchmark => plot_file do
  plot
end
