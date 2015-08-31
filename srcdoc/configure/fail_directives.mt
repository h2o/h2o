? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Fail Directives")->(sub {

<p>
This document describes the configuration directives of the fail handler.
</p>

<?
$ctx->{directive}->(
    name      => "fail",
     levels    => [ qw(path) ],
     desc      => q{Aborts the requests with the given status},
)->(sub {
?>
<p>
The directive aborts request processing and sends an error response with the given status.
</p>
<p>
The argument should be a valid HTTP error code (400 to 417, 426, 500 to 505).
</p>
<?= $ctx->{example}->('Reject requests on unknown hosts', <<'EOT');
hosts:
    default:
      /:
        fail: 403
    "example.com:80":
        paths:
            "/":
                file.dir: /path/to/doc-root
EOT
?>

? })

? })
