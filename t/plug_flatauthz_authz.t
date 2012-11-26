use strict;
use warnings;
use File::HomeDir::Test;
use File::Temp qw( tempdir );
use File::Spec;
use File::Touch qw( touch );
use Test::PlugAuth::Plugin::Authz;

my $tempdir = tempdir( CLEANUP => 1);

run_tests 'FlatAuthz';
