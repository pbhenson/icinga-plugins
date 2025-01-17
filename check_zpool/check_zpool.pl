#!/usr/bin/perl

# Copyright (c) 2024, Paul B. Henson <henson@acm.org>

use strict;
use warnings;

use Monitoring::Plugin ();
use Time::Piece ();

my $VERSION = '0.5';

my $thresholds = {
	'*' => {
				capacity => { w => 70, c => 80 },
				frag => { w => 50, c => 75 },
				leaked => { w => 0, c => 0 },
				scrub => { w => 35, c => 70 },
				cksum_err => { w => 0, c => 10 },
				read_err => { w => 0, c => 10 },
				write_err => { w => 0, c => 10 },
	}
};

my $plugin = Monitoring::Plugin->new(
	usage => "Usage: %s [-v|--verbose] [-t|--timeout <timeout>] [-i|--include <zpool>] " .
				"[-e|--exclude <zpool>] [-w|--warning <pool.category.threshold> " .
				"[-c|--critical <pool.category.threshold>]",
	version => $VERSION,
	url => "https://github.com/pbhenson/icinga-plugins",
	blurb => "check zfs zpool status",
	extra => q{
		[ Need to explain categories and thresholds here ]
	},
);

$plugin->add_arg(
	spec => "include|i=s@",
	help => "zfs pool to check",
);

$plugin->add_arg(
	spec => "exclude|e=s@",
	help => "zfs pool not to check",
);

$plugin->add_arg(
	spec => "warning|w=s@",
	help => "set warning threshold in format <pool.category.threshold>",
);

$plugin->add_arg(
	spec => "critical|c=s@",
	help => "set critical threshold in format <pool.category.threshold>",
);

$plugin->getopts();
my $opts = $plugin->opts();

my $include_pools = $opts->include();
if (defined($include_pools)) {
	$include_pools = { map { $_ => undef } @{$include_pools} };
}

my $exclude_pools = $opts->exclude();
if (defined($exclude_pools)) {
	$exclude_pools = { map { $_ => undef } @{$exclude_pools} };
}

if (defined($opts->warning())) {
	foreach my $w_opt (@{$opts->warning()}) {
		my ($pool, $category, $threshold) = split(/\./, $w_opt);
			if (exists($thresholds->{'*'}{$category})) {
				$thresholds->{$pool}{$category}{w} = $threshold;
			}
			else {
				$plugin->plugin_die("invalid category $category");
			}
	}
}
if (defined($opts->critical())) {
	foreach my $c_opt (@{$opts->critical()}) {
		my ($pool, $category, $threshold) = split(/\./, $c_opt);
			if (exists($thresholds->{'*'}{$category})) {
				$thresholds->{$pool}{$category}{c} = $threshold;
			}
			else {
				$plugin->plugin_die("invalid category $category");
			}
	}
}

my ($status, $output) = read_pipe(split(/ /, 'zpool list -H -o name,capacity,fragmentation,leaked,health'));

if ($status < 0) {
	$plugin->plugin_die("failed to execute zpool list");
}
elsif ($status != 1) {
	if ($opts->verbose()) {
		print STDERR "zpool list failed, output:\n";
		print STDERR "\t$_\n" foreach (@{$output});
	}
	$plugin->plugin_die('zpool list failed');
}

my $found_pool = 0;
my $rcode = Monitoring::Plugin::OK;
my $message;

foreach my $line (@{$output}) {
	my @line = split(/\t/, $line);
	my $pool = {};

	foreach my $key (qw(name capacity frag leaked health)) {
		$pool->{$key} = shift(@line);
	}

	$pool->{capacity} =~ s/%$//;
	$pool->{frag} =~ s/%$//;

	if ((!defined($include_pools) || exists($include_pools->{$pool->{name}})) &&
			(!defined($exclude_pools) || !exists($exclude_pools->{$pool->{name}}))) {
		$found_pool++;

		my $rcode = Monitoring::Plugin::OK;
		my $message = "$pool->{name}: H=$pool->{health}, C=$pool->{capacity}%";
		$message .= ", F$pool->{frag}%, L=$pool->{leaked}";

		if ($pool->{health} ne 'ONLINE') {
			if ($pool->{health} =~ /^(DEGRADED|OFFLINE)$/) {
				$rcode = Monitoring::Plugin::WARNING;
			}
			else {
				$rcode = Monitoring::Plugin::CRITICAL;
			}
		}

		foreach my $key (qw(capacity frag leaked)) {
			my $code = $plugin->check_threshold(check => $pool->{$key},
												warning => exists($thresholds->{$pool->{name}}{$key}{w}) ?
														$thresholds->{$pool->{name}}{$key}{w} :
														$thresholds->{'*'}{$key}{w},
												critical => exists($thresholds->{$pool->{name}}{$key}{c}) ?
														$thresholds->{$pool->{name}}{$key}{c} :
														$thresholds->{'*'}{$key}{c});
			if ($code > $rcode) {
				$rcode = $code;
			}
		}

		my $zp_status = parse_zp_status($pool->{name});

		if (exists($zp_status->{scan})) {
			my $scrub_days;
			my @scrub_flags;
			my $now = time();

			if ($zp_status->{scan} =~ /scrub repaired (.*) in .* with (\d+) errors on (.*)/) {
				my ($repaired, $errors, $time) = ($1, $2, $3);

				my $t;
				eval { $t = Time::Piece->strptime($time, "%a %b %d %H:%M:%S %Y")};
				if (@_) {
					$plugin->plugin_die("failed to parse scan date $time");
				}

				$scrub_days = int(($now - $t->epoch()) / (24*60*60));

				if ($repaired ne '0B') {
					push(@scrub_flags, 'REPAIRED');
				}
				if ($errors != 0) {
					push(@scrub_flags, 'ERRORS');
				}
			}
			elsif ($zp_status->{scan} =~ /resilvered .* in .* with (\d+) errors on/) {
				if ($1 != 0) {
					push(@scrub_flags, 'RSVLR_ERRORS');
				}
			}
			elsif ($zp_status->{scan} =~ /scrub in progress since ([^;]*)/) {
				my $time = $1;

				my $t;
				eval { $t = Time::Piece->strptime($time, "%a %b %d %H:%M:%S %Y")};
				if (@_) {
					$plugin->plugin_die("failed to parse scan date $time");
				}

				$scrub_days = int(($now - $t->epoch()) / (24*60*60));
			}
			elsif ($zp_status->{scan} =~ /resilver in progress since ([^;]*)/) {
					push(@scrub_flags, 'RSVLR');
			}
			
			if (defined($scrub_days)) {
				$message .= ", S=${scrub_days}d";

				my $code = $plugin->check_threshold(check => $scrub_days,
										warning => exists($thresholds->{$pool->{name}}{scrub}{w}) ?
												$thresholds->{$pool->{name}}{scrub}{w} :
												$thresholds->{'*'}{scrub}{w},
										critical => exists($thresholds->{$pool->{name}}{scrub}{c}) ?
												$thresholds->{$pool->{name}}{scrub}{c} :
												$thresholds->{'*'}{scrub}{c});
				if ($code > $rcode) {
					$rcode = $code;
				}
			}
			else {
				$message .= ", S=?d";
				if (Monitoring::Plugin::WARNING > $rcode) {
					$rcode = Monitoring::Plugin::WARNING;
				}
			}
	
			if (@scrub_flags > 0) {
				$message .= " (" . join('|', @scrub_flags) . ")";
				if (Monitoring::Plugin::WARNING > $rcode) {
					$rcode = Monitoring::Plugin::WARNING;
				}
			}
		}
		else {
			$plugin->plugin_die('no scan info found in zpool status');
		}

		if (exists($zp_status->{status})) {
			$message .= ", status pending";
			if (Monitoring::Plugin::WARNING > $rcode) {
				$rcode = Monitoring::Plugin::WARNING;
			}
		}
		if (exists($zp_status->{action})) {
			$message .= ", action pending";
			if (Monitoring::Plugin::WARNING > $rcode) {
				$rcode = Monitoring::Plugin::WARNING;
			}
		}

		if (exists($zp_status->{errors}) && $zp_status->{errors} ne 'No known data errors') {
			$message .= ", errors";
			$rcode = Monitoring::Plugin::CRITICAL;
		}

		my $vdev_errs = {
			cksum_err => 0,
			read_err => 0,
			write_err => 0
		};

		foreach my $vdev (keys(%{$zp_status->{vdevs}})) {
			if ($vdev eq 'spares') {
				foreach my $spare (keys(%{$zp_status->{vdevs}{$vdev}{vdevs}})) {
					if ($zp_status->{vdevs}{$vdev}{vdevs}{$spare}{state} ne 'AVAIL') {
						$message .= ", in-use spare";
						if (Monitoring::Plugin::WARNING > $rcode) {
							$rcode = Monitoring::Plugin::WARNING;
						}
					}
				}

			}
			else {
				foreach (qw(cksum_err read_err write_err)) {
					$vdev_errs->{$_} += $zp_status->{vdevs}{$vdev}{$_};
				}

				if (exists($zp_status->{vdevs}{$vdev}{vdevs})) {
					foreach my $vdev2 (keys(%{$zp_status->{vdevs}{$vdev}{vdevs}})) {
						foreach (qw(cksum_err read_err write_err)) {
							$vdev_errs->{$_} += $zp_status->{vdevs}{$vdev}{vdevs}{$vdev2}{$_};
						}

						if (exists($zp_status->{vdevs}{$vdev}{vdevs}{$vdev2}{vdevs})) {
							foreach my $vdev3 (keys(%{$zp_status->{vdevs}{$vdev}{vdevs}{$vdev2}{vdevs}})) {
								foreach (qw(cksum_err read_err write_err)) {
									$vdev_errs->{$_} +=
										$zp_status->{vdevs}{$vdev}{vdevs}{$vdev2}{vdevs}{$vdev3}{$_};
								}
							}
						}
					}
				}
			}
		}

		foreach my $key (qw(cksum_err read_err write_err)) {
			my $code = $plugin->check_threshold(check => $vdev_errs->{$key},
												warning => exists($thresholds->{$pool->{name}}{$key}{w}) ?
														$thresholds->{$pool->{name}}{$key}{w} :
														$thresholds->{'*'}{$key}{w},
												critical => exists($thresholds->{$pool->{name}}{$key}{c}) ?
														$thresholds->{$pool->{name}}{$key}{c} :
														$thresholds->{'*'}{$key}{c});
			if ($code != Monitoring::Plugin::OK) {
				$message .= ", $key";

				if ($code > $rcode) {
					$rcode = $code;
				}
			}
		}

		$plugin->add_message($rcode, $message);
	}
}

if (!$found_pool) {
	$plugin->plugin_die('no pools found');
}

$plugin->plugin_exit($plugin->check_messages(join_all => ';'));


sub parse_zp_status {
	my ($pool) = @_;

	my ($status, $output) = read_pipe(split(/ /, "zpool status -p $pool"));

	if ($status < 0) {
		$plugin->plugin_die("failed to execute zpool status $pool");
	}
	elsif ($status != 1) {
		if ($opts->verbose()) {
			print STDERR "zpool status $pool failed, output:\n";
			print STDERR "\t$_\n" foreach (@{$output});
		}
		$plugin->plugin_die("zpool status $pool failed");
	}

	my $zp_status = {};
	my $cat;
	my $tlv;
	my $slv;

	foreach my $line (@{$output}) {
		next if $line eq '';

		if ($line =~ s/^ *([a-z]+)://) {
			$cat = $1;
			$line =~ s/^ //;

			if ($cat ne 'config') {
				$zp_status->{$cat} = $line;
			}
		}
		else {
			if ($cat eq 'config') {
				$line =~ s/^\t//;
				next if $line =~ /^NAME/;
				
				if ($line =~ /^([a-zA-z0-9_:.-]+)\s*(.*)/) {
					($tlv, my $stats) = ($1, $2);

					next if $tlv eq 'spares';

					($zp_status->{vdevs}{$tlv}{state}, $zp_status->{vdevs}{$tlv}{read_err},
					 $zp_status->{vdevs}{$tlv}{write_err}, $zp_status->{vdevs}{$tlv}{cksum_err}) =
						split(/\s+/, $stats);
				}
				elsif ($line =~ /^  ([a-zA-z0-9_:.-]+)\s*(.*)/) {
					($slv, my $stats) = ($1, $2);

					my @stats = split(/\s+/, $stats);
					$zp_status->{vdevs}{$tlv}{vdevs}{$slv}{state} = shift(@stats);
					if ($tlv ne 'spares') {
						($zp_status->{vdevs}{$tlv}{vdevs}{$slv}{read_err},
						 $zp_status->{vdevs}{$tlv}{vdevs}{$slv}{write_err},
						 $zp_status->{vdevs}{$tlv}{vdevs}{$slv}{cksum_err}) = @stats;
					}
				}
				elsif ($line =~ /^    ([a-zA-z0-9_:.-]+)\s*(.*)/) {
					my ($vdev, $stats) = ($1, $2);

					my @stats = split(/\s+/, $stats);
					$zp_status->{vdevs}{$tlv}{vdevs}{$slv}{vdevs}{$vdev}{state} = shift(@stats);
					if ($tlv ne 'spares') {
						($zp_status->{vdevs}{$tlv}{vdevs}{$slv}{vdevs}{$vdev}{read_err},
						 $zp_status->{vdevs}{$tlv}{vdevs}{$slv}{vdevs}{$vdev}{write_err},
						 $zp_status->{vdevs}{$tlv}{vdevs}{$slv}{vdevs}{$vdev}{cksum_err}) = @stats;
					}
				}
				else {
					$plugin->plugin_die("unknown zpool status config line: $line");
				}
			}
			else {
				$line =~ s/^\s*//;
				$zp_status->{$cat} .= "; $line";
			}
		}
	}

	return $zp_status;
}

sub safe_pipe {
        my ($command, @options) = @_;

        my $fh;
        my $pid = open($fh, "-|");
        if (defined($pid)) {
                if ($pid) {
                        return $fh;
                }
                else {
                        open(STDERR, ">&STDOUT");
                        exec($command, @options);
                        exit(1);
                }
        }

        return;
}

sub read_pipe {
        my @args = @_;

        my @output;

        my $fh = safe_pipe(@args);

        if (!$fh) {
                return (-1, \@output);
        }

        while (<$fh>) {
                chomp;
                push(@output, $_);
        }

        if (!close($fh) || $? != 0) {
                return (0, \@output);
        }

        return (1, \@output);
}
