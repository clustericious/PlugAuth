use strict;
use warnings;
use Test::PlugAuth::Plugin::Refresh;
$ENV{LOG_LEVEL} = "ERROR";
run_tests 'FlatAuth';
