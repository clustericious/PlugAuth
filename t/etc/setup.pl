use strict;
use warnings;
use 5.010001;

BEGIN {
  unless($INC{'File/HomeDir/Test.pm'})
  {
    eval q{ use File::HomeDir::Test };
    die $@ if $@;
  }
}

$ENV{MOJO_HOME} = "$FindBin::Bin";
$ENV{CLUSTERICIOUS_CONF_DIR} = $ENV{PLUGAUTH_CONF_DIR} // "$FindBin::Bin/etc";
$ENV{LOG_LEVEL} ||= "ERROR";
