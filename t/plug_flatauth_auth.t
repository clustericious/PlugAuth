use strict;
use warnings;
use File::HomeDir::Test;
use Test::PlugAuth::Plugin::Auth;
$ENV{LOG_LEVEL} = "ERROR";
run_tests 'FlatAuth';
