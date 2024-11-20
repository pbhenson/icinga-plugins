#!/usr/bin/perl

# Copyright (c) 2024, Paul B. Henson <henson@acm.org>

use strict;
use warnings;

use Monitoring::Plugin ();
use Net::SIP::Simple ();
use POSIX ();
use Time::HiRes ();

my $VERSION = '0.5';

my $plugin = Monitoring::Plugin->new(
	usage => "Usage: %s [-v|--verbose] --host <host> [--port <port>] " .
				"--user <user> --domain <domain> [--password <password> | --pwfile <file>]" .
				"[--timeout <timeout>] [--warning <seconds>] [--critical <seconds>]",
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

my $sip_ua = Net::SIP::Simple->new(
				registrar => $opts->host() . ":" . $opts->port(),
				domain => $opts->domain(),
				from => $opts->user(),
				auth => [ $opts->user(), $password ],
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
