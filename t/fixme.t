use strict;
use warnings;
use Test::More;
BEGIN {
  eval q{ use Test::Fixme };
  plan skip_all => 'test requires Test::Fixme' if $@;
};

run_tests(
  where => 'lib',
  match => 'FIXME',
);
