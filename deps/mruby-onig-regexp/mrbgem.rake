MRuby::Gem::Specification.new('mruby-onig-regexp') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'

  spec.linker.libraries << 'onig'

  next if build.kind_of? MRuby::CrossBuild
  if build.cc.respond_to? :search_header_path
    next if build.cc.search_header_path 'oniguruma.h'
  end

  require 'open3'
  require 'open-uri'

  version = '5.15.0'
  oniguruma_dir = "#{build_dir}/Onigmo-Onigmo-#{version}"
  oniguruma_lib = libfile "#{oniguruma_dir}/.libs/libonig"
  header = "#{oniguruma_dir}/oniguruma.h"

  task :clean do
    FileUtils.rm_rf [oniguruma_dir]
  end

  file header do |t|
    FileUtils.mkdir_p oniguruma_dir

    _pp 'getting', "onig-#{version}"
    begin
      FileUtils.mkdir_p build_dir
      Dir.chdir(build_dir) do
        File.open("onig-#{version}.tar.gz", 'wb') do |f|
          open("https://github.com/k-takata/Onigmo/archive/Onigmo-#{version}.tar.gz", "accept-encoding" => "none") do |io|
            f.write io.read
          end
        end

        _pp 'extracting', "onig-#{version}"
        `gzip -dc onig-#{version}.tar.gz | tar xf -`
        raise IOError unless $?.exitstatus
      end
    rescue IOError
      File.delete "onig-#{version}.tar.gz"
      exit(-1)
    end
  end

  def run_command(env, command)
    STDOUT.sync = true
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  file oniguruma_lib => header do |t|
    Dir.chdir(oniguruma_dir) do
      e = {
        'CC' => "#{spec.build.cc.command} #{spec.build.cc.flags.join(' ')}",
        'CXX' => "#{spec.build.cxx.command} #{spec.build.cxx.flags.join(' ')}",
        'LD' => "#{spec.build.linker.command} #{spec.build.linker.flags.join(' ')}",
        'AR' => spec.build.archiver.command }
      unless ENV['OS'] == 'Windows_NT'
        _pp 'autotools', oniguruma_dir
        run_command e, './autogen.sh' if File.exists? 'autogen.sh'
        run_command e, './configure --disable-shared --enable-static'
        run_command e, 'make'
      else
        run_command e, 'cmd /c "copy /Y win32 > NUL"'
        run_command e, 'make -f Makefile.mingw'
	  end
    end
  end

  file "#{dir}/src/mruby_onig_regexp.c" => oniguruma_lib
  spec.cc.include_paths << oniguruma_dir
  spec.linker.library_paths << File.dirname(oniguruma_lib)
end
