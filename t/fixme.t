use strict;
use warnings;
use Test::More;
BEGIN {
  eval q{ use Test::Fixme };
  plan skip_all => 'test requires Test::Fixme' if $@;
  plan skip_all => 'Test::Fixme disabled' if $ENV{NO_TEST_FIXME};
};

run_tests(
  where => 'lib',
  match => 'FIXME',
);
