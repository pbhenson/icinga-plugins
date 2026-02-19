#!/usr/bin/perl

# Copyright (c) 2024-2025 Paul B. Henson <henson@acm.org>

use strict;
use warnings;

use IO::Socket::SSL ();
use Monitoring::Plugin ();
use Net::SIP::Simple ();
use POSIX ();
use Time::HiRes ();

my $VERSION = '0.6';

my $plugin = Monitoring::Plugin->new(
	usage => "Usage: %s [-v|--verbose] --host <host> [--port <port>] " .
				"--user <user> --domain <domain> [--password <password> | --pwfile <file>] " .
				"[--timeout <timeout>] [--warning <seconds>] [--critical <seconds>] " .
				"[--tls] [--tls_noverify] [--tls_cn <name>] [--tls_ca_path <path>] " .
				"[--tls_ca_file <path>] [--tls_sni <name>]",
	version => $VERSION,
	url => "https://github.com/pbhenson/icinga-plugins",
	blurb => "check sip server registration operation",
);

$plugin->add_arg(
	spec => "host=s",
	help => "host to check",
	required => 1,
);

$plugin->add_arg(
	spec => "port=i",
	help => "port to check (default: 5060)",
	default => 5060,
);

$plugin->add_arg(
	spec => "user=s",
	help => "sip user",
	required => 1,
);

$plugin->add_arg(
	spec => "domain=s",
	help => "sip domain",
	required => 1,
);

$plugin->add_arg(
	spec => "password=s",
	help => "sip user password",
);

$plugin->add_arg(
	spec => "pwfile=s",
	help => "file containing sip user password",
);

$plugin->add_arg(
	spec => "warning=i",
	help => "time (in seconds) to generate warning alert (default: 5)",
	default => 5,
);

$plugin->add_arg(
	spec => "critical=i",
	help => "time (in seconds) to generate critical alert (default: 10)",
	default => 10,
);

$plugin->add_arg(
	spec => "tls",
	help => "enable TLS on connection",
);

$plugin->add_arg(
	spec => "tls_noverify",
	help => "do not verify peer certificate",
);

$plugin->add_arg(
	spec => "tls_cn=s",
	help => "specific CN value to verify on peer certificate",
);

$plugin->add_arg(
	spec => "tls_ca_path=s",
	help => "path to CA directory",
);

$plugin->add_arg(
	spec => "tls_ca_file=s",
	help => "path to CA file",
);

$plugin->add_arg(
	spec => "tls_sni=s",
	help => "hostname to specify to peer via SNI",
);

$plugin->getopts();
my $opts = $plugin->opts();

my $password;
if (defined($opts->password())) {
	$password = $opts->password();
}
elsif (defined($opts->pwfile())) {
	open(PWFILE, '<' . $opts->pwfile()) or
		$plugin->plugin_die("opening " . $opts->pwfile() . " - $!");

	$password = <PWFILE>;
	chomp($password);

	close(PWFILE);
}
else {
	$plugin->plugin_die("password or pwfile required");
}

my $registrar = $opts->host() . ":" . $opts->port();

my $tls;
if (defined($opts->tls())) {
	$registrar .= ';transport=tls';

	$tls = {};
	if (defined($opts->tls_noverify())) {
		$tls->{SSL_verify_mode} = IO::Socket::SSL::SSL_VERIFY_NONE;
	}
	if (defined($opts->tls_cn())) {
		$tls->{SSL_verifycn_name} = $opts->tls_cn();
	}
	if (defined($opts->tls_ca_path())) {
		$tls->{SSL_ca_path} = $opts->tls_ca_path();
	}
	if (defined($opts->tls_ca_file())) {
		$tls->{SSL_ca_file} = $opts->tls_ca_file();
	}
	if (defined($opts->tls_sni())) {
		$tls->{SSL_hostname} = $opts->tls_sni();
	}
}

my $sip_ua = Net::SIP::Simple->new(
				registrar => $registrar,
				domain => $opts->domain(),
				from => 'sip:' . $opts->user() . '@' . $opts->domain(),
				contact => 'sip:' . $opts->user() . '@' . $opts->domain(),
				auth => [ $opts->user(), $password ],
				tls => $tls,
);

my ($start, $end, $result);
eval {

	my $sigalrm_orig = POSIX::SigAction->new();

	POSIX::sigaction(POSIX->SIGALRM,
						POSIX::SigAction->new(sub { die "connection timeout" }),
						$sigalrm_orig) or die "failed to set alarm";


	alarm($opts->timeout());
	$start = Time::HiRes::time();
	$result = $sip_ua->register();
	$end = Time::HiRes::time();
	alarm(0);

	POSIX::sigaction(POSIX->SIGALRM, $sigalrm_orig) or
		die "failed to restore alarm";

};

if ($@) {
	my $message = $@;
	$message =~ s/ at .* line \d+\.$//;

	$plugin->add_message(Monitoring::Plugin::CRITICAL, $message);
}
elsif (!defined($result)) {
	$plugin->add_message(Monitoring::Plugin::CRITICAL, $sip_ua->error());
}
else {
	my $time = sprintf("%0.3f", $end-$start);
	$plugin->add_message(
		$plugin->check_threshold(check => $time, warning => $opts->warning(), critical => $opts->critical()),
		"$time seconds");
}

$plugin->plugin_exit($plugin->check_messages());
