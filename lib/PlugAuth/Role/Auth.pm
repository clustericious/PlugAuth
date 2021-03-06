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
 with 'PlugAuth::Role::Auth';
 
 # accept user = larry and pass = wall only.
 sub check_credentials {
   my($self, $user, $pass) = @_;
   return 1 if $user eq 'larry' && $pass eq 'wall';
   return $self->deligate_check_credentials($user, $pass);
 }
 
 # only one user, larry
 sub all_users { qw( larry ) }
 
 1;

=head1 DESCRIPTION

Use this role when writing PlugAuth plugins that manage 
authentication (ie. determine the identify of the user).

=head1 REQUIRED ABSTRACT METHODS

These methods must be implemented by your class.

=head2 $plugin-E<gt>check_credentials( $user, $pass )

Return 1 if the password is correct for the given user.

Return 0 otherwise.

=cut

requires qw( check_credentials );

=head1 OPTIONAL ABSTRACT METHODS

These methods may be implemented by your class.

=head2 $plugin-E<gt>all_users

Returns the list of all users known to your plugin.  If
this cannot be determined, then return an empty list.

=cut

sub all_users { () }

=head2 $plugin-E<gt>create_user( $user, $password )

Create the given user with the given password.  Return 1
on success, return 0 on failure.

=cut

sub create_user
{
  my $next_auth = shift->next_auth;
  return 0 unless defined $next_auth;
  $next_auth->create_user(@_);
}

=head2 $plugin-E<gt>create_user_cb( $user, $password, $cb )

Create user with call back.  This works like C<create_user>, but
it calls the callback while your plugin still has a lock on the
user database (if applicable).  If this method is implemented,
then L<PlugAuth> can create users who belong to specific groups
as one atomic action.  If you do not implement this method then
the server will return 501 Not Implemented.

=cut

sub _find_create_user_cb
{
  my $self = shift;
  return $self if $self->can('create_user_cb');
  my $next = $self->next_auth;
  return $next ? $next->_find_create_user_cb : ();
}

=head2 $plugin-E<gt>change_password( $user, $password )

Change the password of the given user.  Return 1 on
success, return 0 on failure.

=cut

sub change_password
{
  my $next_auth = shift->next_auth;
  return 0 unless defined $next_auth;
  $next_auth->change_password(@_);
}

=head2 $plugin-E<gt>delete_user( $user )

Delete the given user.  Return 1 on success, return 0 on failure.

=cut

sub delete_user
{
  my $next_auth = shift->next_auth;
  return 0 unless defined $next_auth;
  $next_auth->delete_user(@_);
}

=head1 METHODS

=head2 $plugin-E<gt>next_auth

Returns the next authentication plugin.  May be undef if
there is no next authentication plugin.

=cut

sub next_auth
{
  my($self, $new_value) = @_;
  $self->{next_auth} = $new_value if defined $new_value;
  $self->{next_auth};
}

=head2 $plugin-E<gt>deligate_check_credentials( $user, $pass )

Delegate to the next authentication plugin.  Call this method if your plugins
authentication has failed if your plugin is not authoritative.

=cut

sub deligate_check_credentials
{
  my($self, $user, $pass) = @_;
  my $next_auth = $self->next_auth;
  return 0 unless defined $next_auth;
  return $next_auth->check_credentials($user, $pass);
}

around all_users => sub {
  my($orig, $self) = @_;
  my $next_auth = $self->next_auth;
  return $orig->($self) unless defined $next_auth;
  return ($orig->($self), $next_auth->all_users);
};

1;

=head1 SEE ALSO

L<PlugAuth>,
L<PlugAuth::Guide::Plugin>,
L<Test::PlugAuth::Plugin::Auth>

=cut
