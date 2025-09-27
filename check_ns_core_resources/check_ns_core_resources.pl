#!/usr/bin/perl

# Copyright (c) 2025, Paul B. Henson <henson@acm.org>

use strict;
use warnings;

use DBI ();
use Monitoring::Plugin ();

my $VERSION = '0.5';

my $verbose = 0;
my $host = 'localhost';
my $user = getpwuid($>);
my $password = '';
my $number = 10;

my $thresholds = {
	rxpkt => { w => 10, c => 20 },
	txpkt => { w => 10, c => 20 },
	pkt_pool => { w => 25, c => 50 },
	sess_pool => { w => 40, c => 50 },
	sbus => { w => 8, c => 10 },
};

my $plugin = Monitoring::Plugin->new(
	usage => "Usage: %s [-v|--verbose] [-h|--host <hostname>] [-u|--user] <username>] " .
				"[--password <password> | --pwfile <file>] [-n|--number <number>] " .
				"[-w|--warning <category.threshold>] [-c|--critical <category.threshold>]",
	version => $VERSION,
	url => "https://github.com/pbhenson/icinga-plugins",
	blurb => "check netsapiens core resource usage",
	extra => q{
		[ Need to explain categories and thresholds here ]
	},
);

$plugin->add_arg(
	spec => "host|h=s",
	help => "set mysql server hostname (default localhost)",
);

$plugin->add_arg(
	spec => "user|u=s",
	help => "set mysql username (default user running script)",
);

$plugin->add_arg(
	spec => "password|p=s",
	help => "set mysql password (default none, unix socket auth)",
);

$plugin->add_arg(
	spec => "pwfile=s",
	help => "file containing mysql user password",
);

$plugin->add_arg(
	spec => "number|n=i",
	help => "number of records to average over (default 10)",
);

$plugin->add_arg(
	spec => "warning|w=s@",
	help => "set warning threshold in format <category.threshold>",
);

$plugin->add_arg(
	spec => "critical|c=s@",
	help => "set critical threshold in format <category.threshold>",
);

$plugin->getopts();
my $opts = $plugin->opts();

$verbose = $opts->verbose() if defined($opts->verbose());
$host = $opts->host() if defined($opts->host());
$user = $opts->user() if defined($opts->user());

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

if(defined($opts->number())) {
	$number = $opts->number();
	$plugin->plugin_die("invalid number $number") unless $number > 0;
}

if (defined($opts->warning())) {
	foreach my $w_opt (@{$opts->warning()}) {
		my ($category, $threshold) = split(/\./, $w_opt);
			if (exists($thresholds->{$category})) {
				$thresholds->{$category}{w} = $threshold;
			}
			else {
				$plugin->plugin_die("invalid category $category");
			}
	}
}
if (defined($opts->critical())) {
	foreach my $c_opt (@{$opts->critical()}) {
		my ($category, $threshold) = split(/\./, $c_opt);
			if (exists($thresholds->{$category})) {
				$thresholds->{$category}{c} = $threshold;
			}
			else {
				$plugin->plugin_die("invalid category $category");
			}
	}
}

my $sql = qq{
SELECT
	ROUND(SUM(rxpkt_fifo) / $number, 2) as rxpkt,
	ROUND(SUM(txpkt_fifo) / $number, 2) as txpkt,
	ROUND((SUM(pkt_oop) / $number) /
		(
			SELECT config_value FROM config_config WHERE config_name = 'PacketPoolSize'
			UNION
			SELECT '20000' WHERE NOT EXISTS
				(
					SELECT 1 FROM config_config WHERE config_name = 'PacketPoolSize'
				)
		), 2) as pkt_pool,
	ROUND(SUM(fifo_sbus_snd) / $number, 2) as sbus,
	ROUND((SUM(session_connected) / $number) /
		(
			SELECT config_value FROM config_config WHERE config_name = 'SessionPoolSize'
			UNION
			SELECT '2000' WHERE NOT EXISTS
				(
					SELECT 1 FROM config_config WHERE config_name = 'SessionPoolSize'
				)
		), 2) as sess_pool
 FROM (
	SELECT rxpkt_fifo,
			txpkt_fifo,
			pkt_oop,
			fifo_sbus_snd,
			session_connected
	FROM status
	ORDER BY status_time DESC
	LIMIT $number
	) as SUMS;
};

my $dbh = DBI->connect("dbi:mysql:database=SiPbxDomain;host=$host",	$user, $password, { PrintError => 0 }) or
	$plugin->plugin_die("failed to connect to $host - $DBI::errstr ($DBI::err)");

my $qh = $dbh->prepare($sql) or
	$plugin->plugin_die("failed to prepare query - $DBI::errstr ($DBI::err)");

$qh->execute() or
	 $plugin->plugin_die("failed to execute query - $DBI::errstr ($DBI::err)");

my $row = $qh->fetchrow_hashref() or
	$plugin->plugin_die("no query results");

foreach my $key (sort(keys(%{$row}))) {
	my $rcode = Monitoring::Plugin::OK;
	my $value = $row->{$key};

	my $code = $plugin->check_threshold(check => $value,
										warning => $thresholds->{$key}{w},
										critical => $thresholds->{$key}{c});
	if ($code > $rcode) {
		$rcode = $code;
	}

	$plugin->add_message($rcode, "$key=$value");
}

$plugin->plugin_exit($plugin->check_messages(join_all => ';'));
