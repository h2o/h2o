? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Mruby Directives")->(sub {

<p>
The following are the configuration directives of the mruby handler.
Please refer to <a href="configure/mruby.html">Using mruby</a> to find out how to write handlers using mruby.
</p>

<?
$ctx->{directive}->(
    name     => "mruby.handler",
    levels   => [ qw(path) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/mruby_directives.html#mruby.handler-file"><code>mruby.handler-file</code></a>
EOT
    desc     => <<'EOT',
Upon start-up evaluates given mruby expression, and uses the returned mruby object to handle the incoming requests.
EOT
)->(sub {
?>

<?= $ctx->{example}->('Hello-world in mruby', <<'EOT')
mruby.handler: |
  Proc.new do |env|
    [200, {'content-type' => 'text/plain'}, ["Hello world\n"]]
  end
EOT
?>

<p>
Note that the provided expression is evaluated more than once (typically for every thread that accepts incoming connections).
</p>
? })

<?
$ctx->{directive}->(
    name     => "mruby.handler-file",
    levels   => [ qw(path) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/mruby_directives.html#mruby.handler"><code>mruby.handler</code></a>
EOT
    desc     => <<'EOT',
Upon start-up evaluates given mruby file, and uses the returned mruby object to handle the incoming requests.
EOT
)->(sub {
?>

<?= $ctx->{example}->('Hello-world in mruby', <<'EOT')
mruby.handler-file: /path/to/my-mruby-handler.rb
EOT
?>

<p>
Note that the provided expression is evaluated more than once (typically for every thread that accepts incoming connections).
</p>
? })

? })
