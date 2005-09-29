#!/usr/bin/perl
umask(022);

chomp($hostname = `/bin/hostname --long`);

#
# Check to see if any other instance is already running - such as if cron
# flipped out on sysmon
#
open( IN, "ps -efl|" );
while ( $line = <IN> )
{
	next if ( $line !~ /perl/ );
	next if ( index( $line, " $$ " ) >= 0 );

	if ( $line =~ /process-servers.pl/o )
	{
		print "Another instance is running, exiting.\n";
		exit(0);
	}
}
close(IN);

#
# Process each server
#
open( STDERR, ">&STDOUT" );
$server_count = 0;

my %dirs = ();
opendir( LOCAL, "/local" );
while ( $entry = readdir(LOCAL) )
{
	if ( $entry =~ /^apache-root.*/o )
	{
		my $dir  = "/local/$entry";
		my $user = undef;
		my $name = undef;

		open( IN, "$dir/conf/httpd.conf" );
		while ( chomp( $line = <IN> ) )
		{
			if ( $line =~ /user\s+(.*?)\s*$/io )
			{
				$user = $1;
			}

			if ( !$name && $line =~ /servername\s+(.*?)\s*$/io )
			{
				$name = $1;
			}
		}
		close(IN);

		if ($user)
		{
			$users{$dir} = $user;
		}
		if ($name)
		{
			$names{$dir} = $name;
		}

		#print "Got $dir => $user => $name\n";
	}
}
if ( -e "/local/ezproxy" )
{
	$users{"/local/ezproxy"} = "ezproxy";
}
if ( -e "/local/blackboard" )
{
	my @tmp = stat("/local/blackboard");
	$users{"/local/blackboard"} = getpwuid( $tmp[4] );
}
if ( -e "/local/realsystem-root/realsystem-9" )
{
	my @tmp = stat("/local/realsystem-root/realsystem-9");
	$users{"/local/realsystem-root/realsystem-9"} = getpwuid( $tmp[4] );
}

foreach $dir ( sort( keys(%users) ) )
{
	my $host   = $hostname;
	my $name   = $names{$dir};
	my $userid = $users{$dir};

	print "Checking for server type in $dir.\n";

	if (   -e "$dir/logs"
		&& -e "$dir/conf"
		&& -e "$dir/restart"
		&& -e "$dir/conf/httpd.conf" )
	{
		print "Got an apache server: $host - $dir - $userid - $name\n";
		&process_apache_server( $host, $dir, $userid, $name );
		$server_count++;
	}
	elsif ( -e "$dir/Logs" && -e "$dir/Bin" && -e "$dir/Plugins" )
	{
		print "Got a realsystem server: $host - $dir - $userid - $name\n";
		&process_realsystem_server( $host, $dir, $userid, $name );
		$server_count++;
	}
	elsif (-e "$dir/tools/admin/ServiceController.sh"
		&& -e "$dir/logs/bb-services-log.txt" )
	{
		print "Got a blackboard 6.x server: $host - $dir - $userid - $name\n";
		&process_bb6_server( $host, $dir, $userid, $name );
		$server_count++;
	}
	elsif ( -e "$dir/ezproxy" && -e "$dir/ezproxy.log" )
	{
		print "Got a ezproxy server: $host - $dir - $userid - $name\n";
		&process_ezproxy_server( $host, $dir, $userid, $name );
		$server_count++;
	}
	else
	{
		print "Did not match any known server type.\n";
	}
}

if ( $server_count == 0 )
{
	print "Warning - no servers found on this host.\n";
}

#
# Utility routines and routines for processing each type of app server
#
sub process_apache_server
{
	my ( $host, $dir, $userid, $name ) = @_;
	print "Processing: $host | $dir | $userid | $name\n";

	chdir("$dir/logs") || print "unable to chdir to $dir/logs" && return;
	if ( !-e "access_log" && !-e "error_log" && !-e "pidfile" && !-e "split" )
	{
		print "Not a log directory. Failed.\n";
		return;
	}

	#
	# switch to effective id of server first
	#
	@tmp = getpwnam($userid);
	$uid = $tmp[2];
	$gid = $tmp[3];
	if ( $uid == 0 )
	{
		print "Couldn't get uid. Returning.\n";
		return;
	}
	else
	{
		print "UID: $uid  GID: $gid\n";
	}

	#
	# Fix ownership of files in server log dir
	#
	print "Fixing log dir permissions.\n";
	system("chown -R $uid $dir/logs/.");
	system("chgrp -R 0 $dir/logs/.");
	system("chown root:root $dir/logs/.");
	system("chown root:root $dir/logs/pidfile");
	system("chmod -R go-rwx $dir/logs/.");
	system("chmod go+x $dir/logs/.");
	print "Done fixing permissions.\n";

	#
	# lose privs
	#
	$> = $uid;

	#
	# Attempt to process standard files
	#
	foreach $log ( "access_log", "error_log", "ssl_engine_log" )
	{
		if ( -e "$dir/logs/$log" )
		{
			&ProcessSingleLog( $log, "$dir/logs/$log" );
		}
	}

	#
	# Attempt to process any split files
	#
	opendir( LOGDIR, "$dir/logs/split" );
	while ( $file = readdir(LOGDIR) )
	{
		next if ( !-f "$dir/logs/split/$file" );
		next if ( $file =~ /\.tmp/ );
		next if ( $file =~ /\.old/ );
		
		if ( $file =~ /\.queue$/o )
		{
			my @tmp = stat("$dir/logs/split/$file");
			if ( $#tmp && $tmp[7] == 0 )
			{
				unlink("$dir/logs/split/$file");
			}
			next;
		}

		if ( $file =~ m|^(.*_log)\.(.*)$|o )
		{
			my $logname = $1;
			my $vname   = $2;

			&ProcessSingleLog( $logname, "$dir/logs/split/$file", $vname );
		}
	}

	#
	# clean up
	#
	$> = 0;
}

sub process_bb6_server
{
	my ( $host, $dir, $userid, $name ) = @_;
	print "Processing: $host | $dir | $userid | $name\n";

	chdir($dir) || die "failed to cd to server dir";
	if ( !-e "logs/httpd/access_log" && !-e "logs/httpd/error_log" )
	{
		print "Not a log directory. Failed.\n";
		return;
	}

	#
	# switch to effective id of server first
	#
	@tmp = getpwnam($userid);
	$uid = $tmp[2];
	$gid = $tmp[3];
	if ( $uid == 0 )
	{
		print "Couldn't get uid. Returning.\n";
		return;
	}

	#
	# Fix ownership of files in server log dir
	#
	system("chown $uid:0 $dir/logs/httpd/error_log");
	system("chown $uid:0 $dir/logs/httpd/access_log");
	system("chown $uid:0 $dir/logs/httpd/mod_jk.log");

	system("chown $uid:0 $dir/logs/modperl/error_log");
	system("chown $uid:0 $dir/logs/modperl/access_log");

	system("chown $uid:0 $dir/logs/collab-server/collab-server-log.txt");

	system("chown $uid:0 $dir/logs/bb-services-log.txt");

	system("chown $uid:0 $dir/apps/tomcat/logs/catalina.out");

	#
	# lose privs
	#
	$> = $uid;

	#
	# Attempt to process standard files
	#
	&ProcessSingleLog( "access_log", "logs/httpd/access_log" );
	&ProcessSingleLog( "error_log",  "logs/httpd/error_log" );
	&ProcessSingleLog( "mod_jk_log", "logs/httpd/mod_jk.log" );

	&ProcessSingleLog( "modperl-access_log", "logs/modperl/access_log" );
	&ProcessSingleLog( "modperl-error_log",  "logs/modperl/error_log" );

	&ProcessSingleLog( "collab-server-log",
		"logs/collab-server/collab-server-log.txt" );

	&ProcessSingleLog( "bb-services", "logs/bb-services-log.txt" );

	&ProcessSingleLog( "catalina-out", "apps/tomcat/logs/catalina.out" );

	my $catbase = "$dir/apps/tomcat/logs";
	opendir( CAT, $catbase );
	my @catfiles = ();
	while ( $catlog = readdir(CAT) )
	{
		if ( $catlog =~ /catalina_log\.\d+/io )
		{
			push( @catfiles, "apps/tomcat/logs/$catlog" );
			print "Found a catalina log: $catlog\n";
		}
	}
	closedir(CAT);
	@catfiles = sort @catfiles;
	for ( $i = 0; $i <= $#catfiles; $i++ )
	{
		my $catlog = $catfiles[$i];

		&ProcessSingleLog( "catalina-log", $catlog );
		if ( $i < $#catfiles )
		{
			print "Removing rotated $catlog.\n";
			unlink("$dir/$catlog");
		}
	}

	#
	# clean up
	#
	$> = 0;
}

sub process_realsystem_server
{
	my ( $host, $dir, $userid, $name ) = @_;
	print "Processing: $host | $dir | $userid | $name\n";

	chdir("$dir/Logs");
	if (   !-e "rmaccess.log"
		&& !-e "rmerror.log"
		&& !-e "rmserver.pid"
		&& !-e "cache.log" )
	{
		print "Not a log directory. Failed.\n";
		return;
	}

	#
	# switch to effective id of server first
	#
	@tmp = getpwnam($userid);
	$uid = $tmp[2];
	$gid = $tmp[3];
	if ( $uid == 0 )
	{
		print "Couldn't get uid. Returning.\n";
		return;
	}

	#
	# Fix ownership of files in server log dir
	#
	system("chown -R $uid $dir/Logs/.");
	system("chgrp -R 0 $dir/Logs/.");
	system("chown root:root $dir/Logs/.");
	system("chown root:root $dir/Logs/rmserver.pid");
	system("chmod -R go-rwx $dir/Logs/.");
	system("chmod go+x $dir/Logs/.");

	#system("chmod -R go-rwx $dir/logs/.");

	#
	# lose privs
	#
	$> = $uid;

	#
	# Attempt to process standard files
	#
	foreach $log ( "rmaccess.log", "rmerror.log", "cache.log" )
	{
		$logname = $log;
		$logname =~ s|\.log||gio;

		if ( -e "$dir/Logs/$log" )
		{
			&ProcessSingleLog( $logname, "$dir/Logs/$log" );
		}
	}

	#
	# clean up
	#
	$> = 0;
}

sub process_ezproxy_server
{
	my ( $host, $dir, $userid, $name ) = @_;
	print "Processing: $host | $dir | $userid | $name\n";

	chdir($dir) || die "failed to cd to server dir";
	if ( !-e "ezproxy.log" && !-e "httpd/logs/ezproxy" )
	{
		print "Not a log directory. Failed.\n";
		return;
	}

	#
	# switch to effective id of server first
	#
	@tmp = getpwnam($userid);
	$uid = $tmp[2];
	$gid = $tmp[3];
	if ( $uid == 0 )
	{
		print "Couldn't get uid. Returning.\n";
		return;
	}

	#
	# Fix ownership of files in server log dir
	#
	system("chown $uid:0 $dir");
	system("chown $uid:0 $dir/ezproxy.log");
	system("chown $uid:0 $dir/ezproxy.msg");

	#
	# lose privs
	#
	$> = $uid;

	&ProcessSingleLog( "ezproxy-log", "ezproxy.log" );
	&ProcessSingleLog( "ezproxy-msg", "ezproxy.msg" );

	#
	# clean up
	#
	$> = 0;
}

sub ProcessSingleLog
{
	my ( $log_name, $srcfile, $vhost ) = @_;

	# log_name = type of log we are archiving
	# srcfile - path to log to archive

	if ( $vhost eq "" )
	{
		$vhost = "default";
	}

	print "Processing $srcfile - ($vhost):\n";

	#
	# Process the log file itself
	#
	my @tmp = stat($srcfile);
	if ( $#tmp > 0 )    # only do something if exists
	{
		if ( $tmp[7] > 0 )    # and only if non-empty
		{
			my $tmpfile = "/tmp/weblogs.$hostname.$$." . time;
			unlink($tmpfile);

			# Process the log into the dest file
			print "\t$log -tcopy-> $tmpfile\n";
			my $tcopy;
			if ( -e "/home/local/sysmon/tcopy" )
			{
				$tcopy = "/home/local/sysmon/tcopy";
			}
			elsif ( -e "/home/local/sysmon/tools/tcopy" )
			{
				$tcopy = "/home/local/sysmon/tools/tcopy";
			}
			else
			{
				die "Missing tcopy executable.\n";
			}
			system($tcopy, $srcfile, $tmpfile);

			my $msgqueue;
			if ( -e "/home/local/sysmon/msgqueue" )
			{
				$msgqueue = "/home/local/sysmon/msgqueue";
			}
			elsif ( -e "/home/local/sysmon/tools/msgqueue" )
			{
				$msgqueue = "/home/local/sysmon/tools/msgqueue";
			}
			else
			{
				die "Missing msgqueue executable.\n";
			}

			print "\t$tmpfile => sysmon\n";
			my $tmpuid = $<;
			$> = 0;
			if ( fork )
			{
				wait;
			}
			else
			{
				open(STDIN, "<$tmpfile");
				exec($msgqueue, "${srcfile}.queue", "app-log-${vhost}:${log_name}");
				exit 1;
			}
			unlink($tmpfile);
			$< = $tmpuid;

			my @tmp = stat("${srcfile}.queue");
			if ( $tmp[7] == 0 )
			{
				unlink("${srcfile}.queue");
			}
		}
	}

	return;
}

sub mysystem
{
	my $cmd = shift;

	print "+ $cmd\n";
	system($cmd);
}

