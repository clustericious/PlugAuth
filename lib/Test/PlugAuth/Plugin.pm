package Test::PlugAuth::Plugin;

use strict;
use warnings;

# ABSTRACT: Private package for Test::PlugAUth::Plugin::* modules
# VERSION

=head1 SEE ALSO

L<PlugAuth>,
L<Test::PlugAuth::Plugin::Auth>,
L<Test::PlugAuth::Plugin::Authz>,
L<Test::PlugAuth::Plugin::Refresh>

=cut

BEGIN {
  delete $ENV{HARNESS_ACTIVE};

  unless($INC{'File/HomeDir/Test.pm'}) 
  {
    require File::HomeDir::Test;
    File::HomeDir::Test->import;
  }
}

1;
