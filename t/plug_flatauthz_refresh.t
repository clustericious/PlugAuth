use strict;
use warnings;
use Test::More;
BEGIN { 
  eval q{ use Test::PlugAuth::Plugin::Refresh; 1 }
  || plan skip_all => 'test requires Test::PlugAuth::Plugin';
}

run_tests 'FlatAuth';
