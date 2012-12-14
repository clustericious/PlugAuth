use strict;
use warnings;
use v5.10;
eval q{
  require File::HomeDir::Test;
  File::HomeDir::Test->import;
};

delete $ENV{HARNESS_ACTIVE};
$ENV{MOJO_HOME} = "$FindBin::Bin";
$ENV{CLUSTERICIOUS_CONF_DIR} = $ENV{PLUGAUTH_CONF_DIR} // "$FindBin::Bin/etc";
$ENV{LOG_LEVEL} = "ERROR";
