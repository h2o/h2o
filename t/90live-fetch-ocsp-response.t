use strict;
use warnings;
use File::Temp qw(tempfile);
use Test::More;

plan skip_all => "skipping live tests (setenv LIVE_TESTS=1 to run them)"
    unless $ENV{LIVE_TESTS};

my @HOSTS = qw(
    www.verisign.com
    www.thawte.com
    www.cybertrust.ne.jp
    www.comodo.com
    www.godaddy.com
    www.startssl.com
);

for my $host (@HOSTS) {
    subtest $host => sub {
        doit($host);
    };
}

done_testing;

sub doit {
    my $host = shift;
    my $input = do {
        open my $fh, "-|", "openssl s_client -showcerts -host $host -port 443 -CAfile /dev/null < /dev/null 2>&1"
            or die "failed to invoke openssl:$!";
        local $/;
        <$fh>;
    };
    my @certs;
    while ($input =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/sg) {
        push @certs, $1;
    }
    ok @certs >= 2, "chain has more than 2 certificates";

    my ($cert_fh, $cert_fn) = tempfile(UNLINK => 1);
    print $cert_fh join "\n", @certs;
    close $cert_fh;

    my $ret = system("share/h2o/fetch-ocsp-response $cert_fn > /dev/null");
    if ($ret == 0) {
        pass "successfully fetched and verified OCSP response";
    } else {
        fail "fetch-ocsp-response exitted with status:$?";
    }
}
