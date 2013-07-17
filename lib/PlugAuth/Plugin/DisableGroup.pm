package PlugAuth::Plugin::DisableGroup;

use strict;
use warnings;
use Role::Tiny::With;

# ABSTRACT: Disable accounts which belong to a group
our $VERSION = '0.20_01'; # VERSION


with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';

sub init
{
  my($self) = @_;
  $self->{group} = $self->plugin_config->{group} // 'disabled';
}

sub check_credentials
{
  my($self, $user, $pass) = @_;
  return 0 if grep { lc($_) eq $self->{group} } @{ $self->app->authz->groups_for_user($user) };
  $self->deligate_check_credentials($user, $pass);
}

1;

__END__
=pod

=head1 NAME

PlugAuth::Plugin::DisableGroup - Disable accounts which belong to a group

=head1 VERSION

version 0.20_01

=head1 SYNOPSIS

In your PlugAuth.conf:

 ---
 plugins:
   - PlugAuth::Plugin::DisableGroup:
       # the default is "disabled"
       group: disabled
   - PlugAuth::Plugin::FlatAuth: {}

=head1 DESCRIPTION

This plugin disables the authentication for a user when they are in a
specific group (the C<disabled> group if it is not specified in the
configuration file).

Trap for the unwary:

Note that you need to specify a real authentication to chain after 
this plugin (L<PlugAuth::Plugin::FlatAuth> is a good choice).  If
you don't then all authentication will fail.

=head1 AUTHOR

Graham Ollis <gollis@sesda3.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by NASA GSFC.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

