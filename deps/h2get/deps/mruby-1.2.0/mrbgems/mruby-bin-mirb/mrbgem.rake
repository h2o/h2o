MRuby::Gem::Specification.new('mruby-bin-mirb') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mirb command'

  if spec.build.cc.search_header_path 'readline/readline.h'
    spec.cc.defines << "ENABLE_READLINE"
    if spec.build.cc.search_header_path 'termcap.h'
      if MRUBY_BUILD_HOST_IS_CYGWIN || MRUBY_BUILD_HOST_IS_OPENBSD
        if spec.build.cc.search_header_path 'termcap.h'
          if MRUBY_BUILD_HOST_IS_CYGWIN then
            spec.linker.libraries << 'ncurses'
          else
            spec.linker.libraries << 'termcap'
          end
        end
      end
    end
    if RUBY_PLATFORM.include?('netbsd')
      spec.linker.libraries << 'edit'
    else
      spec.linker.libraries << 'readline'
      if spec.build.cc.search_header_path 'curses.h'
        spec.linker.libraries << 'ncurses'
      end
    end
  elsif spec.build.cc.search_header_path 'linenoise.h'
    spec.cc.defines << "ENABLE_LINENOISE"
  end

  spec.bins = %w(mirb)
  spec.add_dependency('mruby-compiler', :core => 'mruby-compiler')
end
