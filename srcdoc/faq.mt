? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>Frequently Asked Questions - H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>Frequently Asked Questions</h2>

<h3>What are the lisense terms?</h3>

<div>
H2O is licensed under <a href="http://opensource.org/licenses/MIT">the MIT license</a>.
</div>
<div>
Portions of the software use following libraries that are also licensed under the MIT license: <a href="https://github.com/h2o/h2o/blob/master/deps/klib/khash.h">khash.h</a>, <a href="https://github.com/h2o/h2o/blob/master/deps/picohttpparser/">PicoHTTPParser</a>, <a href="https://github.com/h2o/h2o/blob/master/deps/yaml/">libyaml</a>.
</div>

<div>
Depending on how H2O is configured, the software links against OpenSSL or LibreSSL, both of which are <a href="https://www.openssl.org/source/license.html">dual-licensed under the OpenSSL License and the original SSLeay license</a>.
</div>

<h3>I have a problem.  Where should I look for answers?</h3>

<div>
<a href="https://github.com/h2o/h2o/labels/FAQ">The issues on GitHub tagged as FAQ</a> is a good place to look at.
</div>

</div>

? })
