? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>Configure - H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>Configure</h2>

<ul style="list-style: none; font-weight: bold;">
<li><a href="configure/quick_start.html">Quick Start</a>
<li><a href="configure/command_options.html">Command Options</a>
<li>Configuration Directives
</ul>

<h3>Configuration Directives</h3>

<p>
Under construction.
For the meantime, please refer to <a href="https://gist.github.com/kazuho/f15b79211ea76f1bf6e5" target="_blank">the output of <code>--help</code></a>.
</p>

</div>

? })
