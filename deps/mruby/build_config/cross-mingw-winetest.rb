
# Cross-compile using MinGW and test using Wine.
#
# Steps:
#
#   1. Install MinGW; 64-bit target seems to work best.
#
#   2. Install Wine.
#
#   3. Run command:
#
#           wine cmd /c echo "Hello world"'
#
#      This will confirm that Wine works and will trigger standard
#      Wine setup, which is slow.
#
#   4. Confirm that drive 'z:' is mapped to your root filesystem.
#      (This is supposed to be a default but it helps to
#      double-check.)  To confirm, run:
#
#           wine cmd /c dir 'z:\\'
#
#      This should give you a DOS-style equivalent of 'ls /'.  If not,
#      you'll need to fix that with winecfg or by adding a symlink to
#      '~/.wine/dosdevices'.
#
#   5. You will likely need to tweak the settings below to work with
#      your configuration unless it is exactly like one of the platforms
#      I've tested on (Ubuntu 20.04 or macOS using brew.)
#
#   6. Run the build command:
#
#           MRUBY_CONFIG=build_config/cross-mingw-winetest.rb rake test
#
#      If all goes well, you should now have Windows executables and a
#      set of passing tests.
#
#
#  Caveats:
#
#    1. This works by using a helper script that rewrites test output
#       to make it look *nix-like and then handing it back to the test
#       cases.  Some of the existing tests were (slightly) modified to
#       make this easier but only for the 'full-core' gembox.  Other
#       gems' bintests may or may not work with the helper script and
#       may or may not be fixable by extending the script.
#
#   2.  MinGW and Wine are both complex and not very consistent so you
#       will likely need to do some fiddling to get things to work.
#
#   3.  This script assumes you are running it on a *nix-style OS.
#
#   4.  I recommend building 64-bit targets only.  Building a 32-bit
#       Windows binary with i686-w64-mingw32 seems to work (at least,
#       it did for me) but the resulting executable failed a number of
#       unit tests due to small errors in some floating point
#       operations.  It's unclear if this indicates more serious problems.
#


MRuby::CrossBuild.new("cross-mingw-winetest") do |conf|
  conf.toolchain :gcc

  conf.host_target = "x86_64-w64-mingw32"

  # Ubuntu 20
  conf.cc.command = "#{conf.host_target}-gcc-posix"

  # macOS+Wine from brew
  #conf.cc.command = "#{conf.host_target}-gcc"

  conf.linker.command = conf.cc.command
  conf.archiver.command = "#{conf.host_target}-gcc-ar"
  conf.exts.executable = ".exe"

  # By default, we compile as static as possible to remove runtime
  # MinGW dependencies; they are probably fixable but it gets
  # complicated.
  conf.cc.flags = ['-static']
  conf.linker.flags += ['-static']

  conf.test_runner do |t|
    thisdir = File.absolute_path( File.dirname(__FILE__) )
    t.command = File.join(thisdir, * %w{ helpers wine_runner.rb})
  end

  conf.gembox "full-core"

  conf.enable_bintest
  conf.enable_test
end
