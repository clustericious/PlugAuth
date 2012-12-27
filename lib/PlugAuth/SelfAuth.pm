package PlugAuth::SelfAuth;

use strict;
use warnings;
use base qw( Mojolicious::Plugins );

# ABSTRACT: Self authentication for PlugAuth
# VERSION

=head1 DESCRIPTION

This class helps provide the self authentication/authorization mechanism
for PlugAuth.

=cut

sub new
{
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  push @{ $self->SUPER::namespaces }, 'PlugAuth::SelfAuth', 'Clustericious::Plugin';
  $self;
}

sub namespaces
{
  shift->SUPER::namespaces;
}

1;
