package PlugAuth::Role::Instance;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth instance plugins
# VERSION

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins that should
be instantiated, rather than used as a collection of
class methods.

=cut

sub new
{
  my($class) = @_;
  bless {}, $class;
}

1;
