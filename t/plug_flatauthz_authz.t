use strict;
use warnings;
use File::HomeDir::Test;
use Test::PlugAuth::Plugin::Authz;
$ENV{LOG_LEVEL} = "ERROR";
run_tests 'FlatAuthz';