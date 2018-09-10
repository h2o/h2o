MRuby.each_target do
  if enable_gems?
    # set up all gems
    gems.each(&:setup)
    gems.check self

    # loader all gems
    self.libmruby << objfile("#{build_dir}/mrbgems/gem_init")
    file objfile("#{build_dir}/mrbgems/gem_init") => ["#{build_dir}/mrbgems/gem_init.c", "#{build_dir}/LEGAL"]
    file "#{build_dir}/mrbgems/gem_init.c" => [MRUBY_CONFIG, __FILE__] do |t|
      FileUtils.mkdir_p "#{build_dir}/mrbgems"
      open(t.name, 'w') do |f|
        gem_func_gems = gems.select { |g| g.generate_functions }
        gem_func_decls = gem_func_gems.each_with_object('') do |g, s|
          s << "void GENERATED_TMP_mrb_#{g.funcname}_gem_init(mrb_state*);\n" \
               "void GENERATED_TMP_mrb_#{g.funcname}_gem_final(mrb_state*);\n"
        end
        gem_init_calls = gem_func_gems.each_with_object('') do |g, s|
          s << "  GENERATED_TMP_mrb_#{g.funcname}_gem_init(mrb);\n"
        end
        gem_final_calls = gem_func_gems.each_with_object('') do |g, s|
          s << "  GENERATED_TMP_mrb_#{g.funcname}_gem_final(mrb);\n"
        end
        f.puts %Q[/*]
        f.puts %Q[ * This file contains a list of all]
        f.puts %Q[ * initializing methods which are]
        f.puts %Q[ * necessary to bootstrap all gems.]
        f.puts %Q[ *]
        f.puts %Q[ * IMPORTANT:]
        f.puts %Q[ *   This file was generated!]
        f.puts %Q[ *   All manual changes will get lost.]
        f.puts %Q[ */]
        f.puts %Q[]
        f.puts %Q[#include <mruby.h>]
        f.puts %Q[]
        f.write gem_func_decls
        unless gem_final_calls.empty?
        f.puts %Q[]
          f.puts %Q[static void]
          f.puts %Q[mrb_final_mrbgems(mrb_state *mrb) {]
          f.write gem_final_calls
          f.puts %Q[}]
        end
        f.puts %Q[]
        f.puts %Q[void]
        f.puts %Q[mrb_init_mrbgems(mrb_state *mrb) {]
        f.write gem_init_calls
        f.puts %Q[  mrb_state_atexit(mrb, mrb_final_mrbgems);] unless gem_final_calls.empty?
        f.puts %Q[}]
      end
    end
  end

  # legal documents
  file "#{build_dir}/LEGAL" => [MRUBY_CONFIG, __FILE__] do |t|
    FileUtils.mkdir_p File.dirname t.name
    open(t.name, 'w+') do |f|
     f.puts <<LEGAL
Copyright (c) #{Time.now.year} mruby developers

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
LEGAL

      if enable_gems?
        f.puts <<GEMS_LEGAL

Additional Licenses

Due to the reason that you choosed additional mruby packages (GEMS),
please check the following additional licenses too:
GEMS_LEGAL

        gems.map do |g|
          authors = [g.authors].flatten.sort.join(", ")
          f.puts
          f.puts "GEM: #{g.name}"
          f.puts "Copyright (c) #{Time.now.year} #{authors}"
          f.puts "License: #{g.licenses}"
        end
      end
    end
  end
end
