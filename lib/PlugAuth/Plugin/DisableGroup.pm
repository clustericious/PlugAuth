package PlugAuth::Plugin::DisableGroup;

use strict;
use warnings;
use Role::Tiny::With;

# ABSTRACT: Disable accounts which belong to a group
# VERSION

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

=cut

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
