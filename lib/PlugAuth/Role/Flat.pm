package PlugAuth::Role::Flat;

use strict;
use warnings;
use Log::Log4perl qw( :easy );
use File::stat qw/stat/;
use Fcntl qw/ :flock /;
use Role::Tiny;

# ABSTRACT: private role used by L<FlatAuth|PlugAuth::Plugin::FlatAuth> and L<FlatAuthz|PlugAuth::Plugin::FlatAuthz>.
# VERSION

my %MTimes;

sub has_changed {
    my $filename = shift;
    -e $filename or LOGDIE "File $filename does not exist";
    my $mtime = stat($filename)->mtime;
    return 0 if $MTimes{$filename} && $MTimes{$filename}==$mtime;
    $MTimes{$filename} = $mtime;
    return 1;
}

sub mark_changed {
    delete $MTimes{$_} for @_;
}

sub read_file { # TODO: cache w/ mtime
    my $class = shift;
    my $filename = shift;
    my %args = @_;
    $args{nest} ||= 0;
    #
    # _read_file:
    #  x : y
    #  z : q
    # returns ( x => y, z => q )
    #
    # _read_file(nest => 1):
    #  a : b,c
    #  d : e,f
    # returns ( x => { b => 1, c => 1 },
    #           d => { e => 1, f => 1 } )
    #
    # _read_file(nest => 2):
    #  a : (b) c,d
    #  a : (g) h,i
    #  d : (e) f,g
    # returns ( a => { b => { c => 1, d => 1 },
    #                { g => { h => 1, i => 1 },
    #           d => { e => { f => 1, g => 1 } );
    # Lines beginning with a # are ignored.
    # All spaces are silently squashed.
    #
    TRACE "reading $filename";
    my %h;
    my $fh = IO::File->new("<$filename");
    flock($fh, LOCK_SH) or WARN "Cannot lock $filename - $!\n";
    for my $line ($fh->getlines) {
        chomp $line;
        $line =~ s/\s//g;
        next if $line =~ /^#/ || !length($line);
        my ($k,$v) = split /:/, $line;
        my $p;
        TRACE "parsing $v";
        ($k,$p) = ( $k =~ m/^(.*)\(([^)]*)\)$/) if $args{nest}==2;
        my %m = ( map { $_ => 1 } split /,/, $v ) if $args{nest};
        if ($args{nest}==0) {
            $h{$k} = $v;
        } elsif ($args{nest}==1) {
            $h{$k} ||= {};
            @{ $h{$k} }{keys %m} = values %m;
        } elsif ($args{nest}==2) {
            $h{$k} ||= {};
            $h{$k}{$p} ||= {};
            @{ $h{$k}{$p} }{keys %m} = values %m;
        }
    }
    return %h;
}

1;
