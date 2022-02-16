? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Install")->(sub {

<h3 id="binary">Installing a Binary Package</h3>

<p>
Thanks to others, H2O is provided as a binary package on some environments.
Therefore you may try to at first install the software using your favorite packaging system, and then resort to installing from source as described below.
</p>

<p>
At the time being, following packages are known to be actively maintained<?= $ctx->{note}->(q{Please open a new issue on <a href="https://github.com/h2o/h2o">Github</a> if you want a new package to get added.}) ?>:
<ul>
<li><a href="https://www.freshports.org/www/h2o">FreeBSD h2o release</a> and <a href="https://www.freshports.org/www/h2o-devel">h2o betas</a></li>
<li><a href="https://formulae.brew.sh/formula/h2o">Homebrew (macOS)</a></li>
<li><a href="https://github.com/tatsushid/h2o-rpm">RPM (Fedora, RHEL/CentOS, OpenSUSE)</a></li>
<li><a href="https://hub.docker.com/r/lkwg82/h2o-http2-server/">Docker Image</a></li>
</ul>
</p>

<h3 id="from-source">Installing from Source</h3>

<p>
First, either download a release version from <a href="https://github.com/h2o/h2o/releases">the releases page</a>, or clone the master branch from <a href="https://github.com/h2o/h2o/">the source repository</a>. When cloning, submodules should also be fetched, e.g., by running <code>git clone --recurse-submodules</code>.
</p>
<p>
Then, build the obtained source using <a href="http://www.cmake.org/">CMake</a><?= $ctx->{note}->("CMake is a popular build tool that can be found as a binary package on most operating systems.") ?>.
</p>

<?= $ctx->{code}->(<< 'EOT')
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

<h3>Installing from Source, using OpenSSL</h3>

<p>
Generally speaking, we believe that using LibreSSL is a better choice for running H2O, since LibreSSL not only is considered to be more secure than OpenSSL but also provides support for new ciphersuites such as <code>chacha20-poly1305</code> which is the preferred method of Google Chrome<?= $ctx->{note}->(q{ref: <a href="https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/">Do the ChaCha: better mobile performance with cryptography</a>}) ?>.  However, it is also true that LibreSSL is slower than OpenSSL on some benchmarks.  So if you are interested in benchmark numbers, using OpenSSL is a reasonable choice.
</p>

<p>
The difficulty in using OpenSSL is that the HTTP/2 specification requires the use of an extension to the TLS protocol named ALPN, which has only been supported since OpenSSL 1.0.2<?= $ctx->{note}->("It is possible to build H2O using prior versions of OpenSSL, but some (if not all) web browsers are known for not using HTTP/2 when connecting to servers configured as such.") ?>.  Therefore it is highly likely that you would need to manually install or upgrade OpenSSL on your system.
</p>

<p>
Once you have installed OpenSSL 1.0.2, it is possible to build H2O that links against the library.
CMake will search for OpenSSL by looking at the default search paths.
</p>

<?= $ctx->{code}->(<< 'EOT')
% mkdir -p build
% cd build
% cmake ..
% make
% sudo make install
EOT
?>

<p>
Two ways exist to specify the directory in which CMake should search for OpenSSL.
The preferred approach is to use the <code>PKG_CONFIG_PATH</code> environment variable.
</p>

<?= $ctx->{code}->(<< 'EOT')
% mkdir -p build
% cd build
% PKG_CONFIG_PATH=/usr/local/openssl-1.0.2/lib/pkgconfig cmake ..
% make
% sudo make install
EOT
?>

<p>
In case your OpenSSL installation does not have the <code>lib/pkgconfig</code> directory, you may use <code>OPENSSL_ROOT_DIR</code> environment variable to specify the root directory of the OpenSSL being installed.  However, it is likely that CMake version 3.1.2 or above is be required when using this approach<?= $ctx->{note}->(q{ref: <a href="https://github.com/h2o/h2o/issues/277">h2o issue #277</a>, <a href="http://public.kitware.com/Bug/view.php?id=15386">CMake issue 0015386</a>}) ?>.
</p>

<?= $ctx->{code}->(<< 'EOT')
% mkdir -p build
% cd build
% OPENSSL_ROOT_DIR=/usr/local/openssl-1.0.2 cmake ..
% make
% sudo make install
EOT
?>

? })
