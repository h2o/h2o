MRuby::Gem::Specification.new('mruby-onig-regexp') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'

  def spec.bundle_onigmo
    return if @onigmo_bundled
    @onigmo_bundled = true

    visualcpp = ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']

    require 'open3'

    # remove libonig, instead link directly against pthread
    unless ENV['OS'] == 'Windows_NT'
      linker.libraries = ['pthread']
    end

    version = '6.1.2'
    oniguruma_dir = "#{build_dir}/onigmo-#{version}"
    oniguruma_lib = libfile "#{oniguruma_dir}/.libs/libonigmo"
    unless ENV['OS'] == 'Windows_NT'
      oniguruma_lib = libfile "#{oniguruma_dir}/.libs/libonigmo"
    else
      if ENV['PROCESSOR_ARCHITECTURE'] == 'AMD64'
        oniguruma_lib = libfile "#{oniguruma_dir}/build_x86-64/libonigmo"
      else
        oniguruma_lib = libfile "#{oniguruma_dir}/build_i686/libonigmo"
      end
    end
    header = "#{oniguruma_dir}/onigmo.h"

    task :clean do
      FileUtils.rm_rf [oniguruma_dir]
    end

    file header do |t|
      FileUtils.mkdir_p oniguruma_dir
      Dir.chdir(build_dir) do
        _pp 'extracting', "Onigmo-#{version}"
        `gzip -dc "#{dir}/Onigmo-#{version}.tar.gz" | tar xf -`
      end
    end

    def run_command(env, command)
      unless system(env, command)
        fail "#{command} failed"
      end
    end

    libonig_objs_dir = "#{oniguruma_dir}/libonig_objs"
    libmruby_a = libfile("#{build.build_dir}/lib/libmruby")
    objext = visualcpp ? '.obj' : '.o'

    file oniguruma_lib => header do |t|
      Dir.chdir(oniguruma_dir) do
        e = {
          'CC' => "#{build.cc.command} #{build.cc.flags.join(' ')}",
          'CXX' => "#{build.cxx.command} #{build.cxx.flags.join(' ')}",
          'LD' => "#{build.linker.command} #{build.linker.flags.join(' ')}",
          'AR' => build.archiver.command }
        unless ENV['OS'] == 'Windows_NT'
          if build.kind_of? MRuby::CrossBuild
            host = "--host #{build.name}"
          end

          _pp 'autotools', oniguruma_dir
          run_command e, './autogen.sh' if File.exists? 'autogen.sh'
          run_command e, "./configure --disable-shared --enable-static #{host}"
          run_command e, 'make'
        else
          run_command e, 'cmd /c "copy /Y win32 > NUL"'
          if visualcpp
            run_command e, 'nmake -f Makefile'
          else
            run_command e, 'make -f Makefile.mingw'
          end
        end
      end

      FileUtils.mkdir_p libonig_objs_dir
      Dir.chdir(libonig_objs_dir) do
        unless visualcpp
          `ar x #{oniguruma_lib}`
        else
          winname = oniguruma_lib.gsub(%'/', '\\')
          `lib -nologo -list #{winname}`.each_line do |line|
            line.chomp!
            `lib -nologo -extract:#{line} #{winname}`
          end
        end
      end
      file libmruby_a => Dir.glob("#{libonig_objs_dir}/*#{objext}")
    end

    file libmruby_a => Dir.glob("#{libonig_objs_dir}/*#{objext}") if File.exists? oniguruma_lib

    task :mruby_onig_regexp_with_compile_option do
      cc.include_paths << oniguruma_dir
      cc.defines += ['HAVE_ONIGMO_H']
    end
    file "#{dir}/src/mruby_onig_regexp.c" => [:mruby_onig_regexp_with_compile_option, oniguruma_lib]
  end

  if spec.respond_to? :search_package and spec.search_package 'onigmo'
    spec.cc.defines += ['HAVE_ONIGMO_H']
    spec.linker.libraries << 'onig'
  elsif spec.respond_to? :search_package and spec.search_package 'oniguruma'
    spec.cc.defines += ['HAVE_ONIGURUMA_H']
    spec.linker.libraries << 'onig'
  elsif build.cc.respond_to? :search_header_path and build.cc.search_header_path 'onigmo.h'
    spec.cc.defines += ['HAVE_ONIGMO_H']
    spec.linker.libraries << 'onigmo'
  elsif build.cc.respond_to? :search_header_path and build.cc.search_header_path 'oniguruma.h'
    spec.cc.defines += ['HAVE_ONIGURUMA_H']
    spec.linker.libraries << 'onig'
  else
    spec.bundle_onigmo
  end
end
