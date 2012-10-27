package PlugAuth::Role::Auth;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth authentication plugins
# VERSION

=head1 SYNOPSIS

 package PlugAuth::Plugin::MyAuth;
 
 use Role::Tiny::With;
 
 with 'PlugAuth::Role::Plugin';
 with 'PlugAuth::Role::Instance';
 with 'PlugAuth::Role::Auth';
 
 # accept user = larry and pass = wall only.
 sub check_credentials {
   my($self, $user, $pass) = @_;
   return 1 if $user eq 'larry' && $pass eq 'wall';
   return $self->deligate_check_credentials($user, $pass);
 }
 
 # only one user, larry
 sub all_users { qw( larry ) }

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins that manage 
authentication (ie. determine the identify of the user).

=cut

requires qw( 
  check_credentials
  all_users
);

=head1 ABSTRACT METHODS

These methods must be implemented by your class.

=head2 $plugin-E<gt>check_credentials( $user, $pass )

Return 1 if the password is correct for the given user.

Return 0 otherwise.

=head2 $plugin-E<gt>all_users

Returns the list of all users known to your plugin.  If
this cannot be determined, then return an empty list.

=head1 METHODS

=head2 $plugin-E<gt>next_auth

Returns the next authentication plugin.  May be undef if
there is no next authentication plugin.

=cut

my %next_auths;

sub next_auth
{
  my($self, $new_value) = @_;
  if(ref($self))
  {
    $self->{next_auth} = $new_value if defined $new_value;
    return $self->{next_auth};
  }
  else
  {
    $next_auths{$self} = $new_value if defined $new_value;
    return $next_auths{$self};
  }
}

=head2 $plugin-E<gt>deligate_check_credentials( $user, $pass )

Deligate to the next auth plugin.  Call this method if your plugins
authentication has failed if your plugin is not authoritative.

=cut

sub deligate_check_credentials
{
  my($self, $user, $pass) = @_;
  my $next_auth = $self->next_auth;
  return 0 unless defined $next_auth;
  return $next_auth->check_credentials($user, $pass);
}

1;
