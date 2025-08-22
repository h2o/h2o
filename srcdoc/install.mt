? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Install")->(sub {

<h3 id="release-policy">Release Policy</h3>

<p>
As of April 2023, we have ceased to release versions.
Rather, the each commit to master branch is considered stable and ready for general use except for the features marked as experimental.
</p>

<h3 id="dependencies">Dependencies</h3>

<p>
H2O requires the following softwares to be installed:
<ul>
<li>C/C++ compiler (GCC or Clang)
<li>CMake
<li>pkg-config
<li>OpenSSL 1.0.2 or later, or a TLS stack compatible with OpenSSL<?= $ctx->{note}->("At the time of writing, H2O can be built with libressl and boringssl.") ?>
<li>zlib
</ul>
</p>

<p>
Additional softwares may be required for using certain features.
As an example, to build the <a href="configure/mruby_directives.html">mruby</a> handler, bison and ruby have to be installed.
</p>

<h3 id="from-source">Installing from Source</h3>

<p>
First, clone the master branch from <a href="https://github.com/h2o/h2o/">the source repository</a> as well as the submodules.
</p>
<?= $ctx->{code}->(<< 'EOT')
% git clone --recurse-submodules https://github.com/h2o/h2o.git
EOT
?>

<p>
Then, build the obtained source using <a href="http://www.cmake.org/">CMake</a><?= $ctx->{note}->("CMake is a popular build tool that can be found as a binary package on most operating systems.") ?>.
</p>

<?= $ctx->{code}->(<< 'EOT')
% cd h2o
% mkdir -p build
% cd build
% cmake ..
% make
% sudo make install
EOT
?>

<p>
When complete, H2O will be installed under <code>/usr/local</code>.
</p>

<p>
Start the installed server using the example configuration to confirm that it actually works (note: without the use of <code>-m</code> option the server runs as a foreground process; press <code>Ctrl-C</code> to stop).
</p>

<?= $ctx->{code}->(<< 'EOT')
% /usr/local/bin/h2o -c examples/h2o/h2o.conf
EOT
?>

<p>
Or if you'd like to start H2O without installing it, you can use the <code>H2O_ROOT</code> environment variable.
</p>

<?= $ctx->{code}->(<< 'EOT')
% H2O_ROOT=$PWD build/h2o -c examples/h2o/h2o.conf
EOT
?>

<p>
The example configuration starts a server that listens to port 8080 (HTTP) and port 8081 (HTTPS).  Try to access the ports using the protocols respectively (note: when accessing via HTTPS it is likely that you would see hostname mismatch errors reported by the web browsers).
</p>

<p>
When complete, proceed to <a href="configure.html">Configure</a> section for how to setup the server.
</p>

<h4>CMake Options</h4>

<p>
Following list shows the interesting arguments recognized by CMake.

<dl>
<dt><code>-DCMAKE_INSTALL_PREFIX=<i>directory</i></code></dt>
<dd>
This option specifies the directory to which H2O will be installed (default: <code>/usr/local</code>).
</dd>
<dt><code>-DWITH_MRUBY=<i>on</i>|<i>off</i></code></dt>
<dd>
This option instructs whether or not to build the standalone server with support for <a href="configure/mruby.html">scripting using mruby</a>.
It is turned on by default if the prerequisites (<a href="https://www.gnu.org/software/bison/">bison</a>, <a href="https://www.ruby-lang.org/">ruby</a> and the development files<?= $ctx->{note}->(q{<code>mkmf</code> - a program for building ruby extensions is required.  In many distributions, the program is packaged as part of <code>ruby-dev<code> or <code>ruby-devel</code> package.}) ?>) are found.
</dl>
<dt><code>-DWITH_DTRACE=<i>on</i>|<i>off</i></code></dt>
<dd>
This option instructs whether or not to enable DTrace support.
It is turned on by default if the prerequisites (<a href="https://sourceware.org/systemtap/">SystemTap</a> on Linux, or DTrace on macOS) are found.
See also <a href="https://github.com/h2o/h2o/wiki/macOS">wiki/macOS</a> to use DTrace on macOS.
</dl>
<dt><code>-DWITH_H2OLOG=<i>on</i>|<i>off</i></code></dt>
<dd>
This option instructs whether or not to enable <code>h2olog(1)</code>> support.
It is turned on by default if the prerequisites are found.
See also <a href="./configure/h2olog.html">h2olog</a> for details.
</dl>
<dt><code>-DOPENSSL_ROOT_DIR=/path/to/openssl</code></dt>
<dd>
On most platforms, OpenSSL is automatically found by the <a href="https://cmake.org/cmake/help/latest/module/FindOpenSSL.html" target=_blank>FindOpenSSL.cmake</a> module.
This option is used when the automatic detection fails or if an alternative version of the TLS stack is to be used.
</dd>
<dt><code>-DCMAKE_C_FLAGS=...</code></dt>
<dd>
This option can be used to add or override the compile options being passed to the C compiler.
As an example, <a href="https://en.wikipedia.org/wiki/AddressSanitizer">AddressSanitizer (ASan)</a> can be enabled when using recent versions of GCC or Clang, by passing <code>-DCMAKE_C_FLAGS="-fsanitize=address -fno-stack-protector -fno-omit-frame-pointer"</code>.
</dd>
<dt><code>-DCMAKE_BUILD_TYPE=Release|Debug</code></dt>
<dd>
This option specifies the build type, <code>Release</code> or <code>Debug</code>.
The default is <code>Release</code>.
</dd>
</p>
<h3 id="binary">Installing a Binary Package</h3>

<p>
Thanks to others, H2O is provided as a binary package on some environments.
Up-to-date versions of H2O might be found at the following locations.
<ul>
<li><a href="https://www.freshports.org/www/h2o">FreeBSD h2o release</a> and <a href="https://www.freshports.org/www/h2o-devel">h2o betas</a></li>
<li><a href="https://formulae.brew.sh/formula/h2o">Homebrew (macOS)</a></li>
<li><a href="https://github.com/tatsushid/h2o-rpm">RPM (Fedora, RHEL/CentOS, OpenSUSE)</a></li>
<li><a href="https://hub.docker.com/r/lkwg82/h2o-http2-server/">Docker Image</a></li>
</ul>
</p>

? })
