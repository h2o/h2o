? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>Install - H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>Install</h2>

<h3>Installing the Binary Distribution</h3>

<div>
Thanks to others, H2O is provided as a binary package on some of the operating systems (e.g. yum, apt-get, brew).

Therefore you may try to at first install the software using your favorite packaging system, and then resort to installing from source as described below.
</div>

<h3>Installing from Source</h3>

<p>
Download a release version from <a href="https://github.com/h2o/h2o/releases">the releases page</a> or clone the master branch from <a href="https://github.com/h2o/h2o/">the source repository</a>, and build it using <a href="http://www.cmake.org/">CMake</a><?= $ctx->{note}->("CMake is a popular build tool that can be found as a binary package on most operating systems.") ?>.
</p>

<?= $ctx->{code}->(<< 'EOT')
% cmake -DWITH_BUNDLED_SSL=on .
% make
% sudo make install
EOT
?>

<p>
When complete, H2O will be installed under <code>/usr/local</code>.
</p>

<p>
Please proceed to <a href="configure.html">Configure</a> section for how to setup the server.
</p>

<h4>CMake Options</h4>

<p>
Following list shows the interesting arguments to CMake.

<dl>
<dt><code>-DWITH_BUNDLED_SSL=<i>on</i>|<i>off</i></code></dt>
<dd>
This option instructs whether or not to use <a href="http://www.libressl.org/">LibreSSL</a> being bundled (default: <code>off</code> if <a href="https://www.openssl.org/">OpenSSL</a> version >= 1.0.2 is found, <code>off</code> if otherwise).  Read the section below for comparison between OpenSSL and LibreSSL.
</dd>
<dt><code>-DCMAKE_INSTALL_PREFIX=<i>directory</i></code></dt>
<dd>
This option specifies the directory to which H2O will be installed (default: <code>/usr/local</code>).
</dd>
</dl>
</p>

<h3>Installing from Source, using OpenSSL</h3>

<p>
Generally speaking, we believe that using LibreSSL is a better choice for running H2O, since LibreSSL not only is considered to be more secure than OpenSSL but also provides support for new ciphersuites such as <code>chacha20-poly1305</code> which is the preferred method of Google Chrome<?= $ctx->{note}->("ref: https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/") ?>.  However, it is also true that LibreSSL is slower than OpenSSL on some benchmarks.  So if you are interested in benchmark numbers, using OpenSSL is a reasonable choice.
</p>

<p>
The difficulty in using OpenSSL is that the HTTP/2 specification requires the use of an extension to the TLS protocol named ALPN, which has only been supported since OpenSSL 1.0.2<?= $ctx->{note}->("It is possible to build H2O using prior versions of OpenSSL, but some (if not all) web browsers are known for not using HTTP/2 when connecting to servers configured as such.") ?>.  Therefore it is highly likely that you would need to manually install or upgrade OpenSSL on your system.
</p>

<p>
Once you have installed OpenSSL 1.0.2, it is possible to build H2O that links against the library.  As an safeguard it is advised to use <code>-DWITH_BUNDLED_SSL</code> set to <code>off</code>, so that the server would not accidentally link against the bundled LibreSSL.
CMake will search for OpenSSL by looking at the default search paths.
</p>

<?= $ctx->{code}->(<< 'EOT')
% cmake -DWITH_BUNDLED_SSL=off
% make
% sudo make install
EOT
?>

<p>
Two ways exist to specify the directory in which CMake should search for OpenSSL.
The preferred approach is to use the <code>PKG_CONFIG_PATH</code> environment variable.
</p>

<?= $ctx->{code}->(<< 'EOT')
% PKG_CONFIG_PATH=/usr/local/openssl-1.0.2/lib/pkgconfig cmake -DWITH_BUNDLED_SSL=off
% make
% sudo make install
EOT
?>

<p>
In case your OpenSSL installation does not have the <code>lib/pkgconfig</code> directory, you may use <code>OPENSSL_ROOT_DIR</code> environment variable to specify the root directory of the OpenSSL being installed.  However, CMake equal to or above version 3.1.2 may be required when using this approach<?= $ctx->{note}->("ref: http://public.kitware.com/Bug/view.php?id=15386") ?>.
</p>

<?= $ctx->{code}->(<< 'EOT')
% OPENSSL_ROOT_DIR=/usr/local/openssl-1.0.2 cmake -DWITH_BUNDLED_SSL=off
% make
% sudo make install
EOT
?>

?= $_mt->render_file("notes.mt")

</div>

? })
