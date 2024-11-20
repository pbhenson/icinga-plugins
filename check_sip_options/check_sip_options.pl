#!/usr/bin/perl

# Copyright (c) 2024, Paul B. Henson <henson@acm.org>

use strict;
use warnings;

use Monitoring::Plugin ();
use Net::SIP ();
use Time::HiRes ();

my $VERSION = '0.5';

my $plugin = Monitoring::Plugin->new(
	usage => "Usage: %s [-v|--verbose] --ip <ip> [--port <port>] [--protocol <protocol>]" .
				"[--to_user <user>] [--from_user <user>]" .
				"[--timeout <timeout>] [--warning <seconds>] [--critical <seconds>]",
	version => $VERSION,
	url => "https://github.com/pbhenson/icinga-plugins",
	blurb => "check sip server availability via OPTIONS ping",
);

$plugin->add_arg(
	spec => "ip=s",
	help => "ip address to check",
	required => 1,
);

$plugin->add_arg(
	spec => "port=i",
	help => "port to check (default: 5060)",
	default => 5060,
);

$plugin->add_arg(
	spec => "protocol=s",
	help => "protocol (default udp)",
	default => 'udp',
);

$plugin->add_arg(
	spec => "to_user=s",
	help => "remote sip user (default icinga)",
	default => 'icinga',
);

$plugin->add_arg(
	spec => "from_user=s",
	help => "local sip user (default icinga)",
	default => 'icinga',
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

my ($remote_sock, $local_endpoint);

eval {
	($remote_sock, $local_endpoint) =
			Net::SIP::Util::create_socket_to($opts->ip() . ':' . $opts->port(),
												$opts->protocol());
};
if ($@) {
	$@ =~ s# at /.*##;
	$plugin->plugin_exit(Monitoring::Plugin::CRITICAL, "internal error - $@");
}

my $ua = Net::SIP::Simple->new(
	leg => $remote_sock,
);

my $start;

my $callback = sub {
	my (undef, undef, $err, $code, $packet, undef, undef) = @_;

	my $end = Time::HiRes::time();

	if ($err) {
		$plugin->add_message(Monitoring::Plugin::CRITICAL, "internal error - $err");
	}
	elsif ($code eq '200') {
		my $time = sprintf("%0.3f", $end - $start);

		$plugin->add_message(
			$plugin->check_threshold(check => $time, warning => $opts->warning(),
										critical => $opts->critical()), "$time seconds");
	}
	else {
		$plugin->add_message(Monitoring::Plugin::CRITICAL, $code . ' ' . $packet->{text});
	}

	$plugin->plugin_exit($plugin->check_messages());
};

$start = Time::HiRes::time();

$ua->{endpoint}->new_request('OPTIONS',
								{
									from => 'sip:' . ($opts->from_user() ne '' ?
												$opts->from_user() . '@' : '') .
												$local_endpoint,
									to => 'sip:' . ($opts->to_user() ne '' ?
											$opts->to_user() . '@' : '') .
											$opts->ip() . ':' . $opts->port(),
								},
								$callback,
);

$ua->loop($opts->timeout());

$plugin->plugin_exit(Monitoring::Plugin::CRITICAL, 'connection timeout');
