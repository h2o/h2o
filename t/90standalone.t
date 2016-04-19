use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use Test::More;
use t::Util;
use Capture::Tiny qw(capture);

subtest "--mruby" => sub {
	plan skip_all => "mruby is not enabled" unless server_features->{mruby};

	my $run = sub {
		my ($code) = @_;
		my ($fh, $fn) = tempfile(UNLINK => 1);
		print $fh $code;
		close $fh;

		return capture {
			system(bindir() . "/h2o", "--mode=test", "--mruby=$fn");
		};
	};

	subtest "stdout / stderr" => sub {
		my ($stdout, $stderr) = $run->(q{
			puts "puts stdout"
			raise "warn stderr"
		});

		like $stdout, qr/puts stdout\n/;
		like $stderr, qr/warn stderr \(RuntimeError\)/;
	};

	subtest "mruby context" => sub {
		local $ENV{H2O_ROOT} = '.';
		my ($stdout, $stderr) = $run->(q{
			p $LOAD_PATH
		});
		like $stdout, qr{\[".", "./share/h2o/mruby"\]};
		is $stderr, '';
	};
};

# avoid no tests run
ok 1;
done_testing;
