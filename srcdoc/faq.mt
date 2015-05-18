? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Frequently Asked Questions")->(sub {

<h3 id="license">What are the license terms?</h3>

<div>
H2O is licensed under <a href="http://opensource.org/licenses/MIT">the MIT license</a>.
</div>
<div>
Portions of the software use following libraries that are also licensed under the MIT license: <a href="https://github.com/h2o/h2o/blob/master/deps/klib/khash.h">khash.h</a>, <a href="https://github.com/h2o/h2o/blob/master/deps/picohttpparser/">PicoHTTPParser</a>, <a href="https://github.com/h2o/h2o/blob/master/deps/yaml/">libyaml</a>.
</div>

<div>
Depending on how H2O is configured, the software links against OpenSSL or LibreSSL, both of which are <a href="https://www.openssl.org/source/license.html">dual-licensed under the OpenSSL License and the original SSLeay license</a>.
</div>

<h3 id="design-docs">Are there any design documents?</h3>

<div>
Please refer to the main developer's <a href="http://www.slideshare.net/kazuho/h2o-20141103pptx" target="_blank">presentation slides</a> at the HTTP/2 conference, and <a href="http://blog.kazuhooku.com" target="_blank">his weblog</a>.
</div>

<h3 id="libh2o">How do I use H2O as a library?</h3>

<div>
<p>
Aside from the standalone server, H2O can also be used as a software library.
The name of the library is <code>libh2o</code>.
</p>
<p>
To build H2O as a library you will need to install the following dependencies:
<ul>
<li><a href="https://github.com/libuv/libuv/">libuv</a> version 1.0 or above</li>
<li><a href="https://www.openssl.org/">OpenSSL</a> version 1.0.2 or above<?= $ctx->{note}->(q{libh2o cannot be linked against the bundled LibreSSL; see <a href="https://github.com/h2o/h2o/issues/290">issue #290</a>}) ?></li>
</ul>
In case the dependencies are installed under a non-standard path, <code>PKG_CONFIG_PATH</code> configuration variable can be used for specifying their paths.  For example, the following snippet builds <code>libh2o</code> using the libraries installed in their respective paths.
</p>

<?= $ctx->{code}->(<< 'EOT')
% PKG_CONFIG_PATH=/usr/local/libuv-1.4/lib/pkgconfig:/usr/local/openssl-1.0.2a/lib/pkgconfig cmake .
% make libh2o
EOT
?>

<p>
For more information, please refer to the <a href="https://github.com/h2o/h2o/labels/libh2o">GitHub issues tagged as libh2o</a>.
</p>
</div>

<h3 id="issues">I have a problem.  Where should I look for answers?</h3>

<div>
Please refer to the <a href="https://github.com/h2o/h2o/labels/FAQ">GitHub issues tagged as FAQ</a>.
</div>

? })
