package PlugAuth::SelfAuth;

use strict;
use warnings;
use base qw( Mojolicious::Plugins );

# ABSTRACT: Self authentication for PlugAuth
our $VERSION = '0.10'; # VERSION


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

__END__

=pod

=head1 NAME

PlugAuth::SelfAuth - Self authentication for PlugAuth

=head1 VERSION

version 0.10

=head1 DESCRIPTION

This class helps provide the self authentication/authorization mechanism
for PlugAuth.

=head1 AUTHOR

Graham Ollis <gollis@sesda3.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by NASA GSFC.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
