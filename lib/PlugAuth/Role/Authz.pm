package PlugAuth::Role::Authz;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth authorization plugins
# VERSION

=head1

Use this role when writing PlugAuth plugins that manage
authorization (ie. determine what the user has authorization
to actually do).

=cut

requires qw( 
  can_user_action_resource
  match_resources
  host_has_tag
  actions
  groups
  all_groups
  users
);

=head1 OPTIONAL ABSTRACT METHODS

These methods may be implemented by your class.

=head2 $plugin-E<gt>create_group( $group, $users )

Create a new group with the given users.  $users is a
comma separated list of user names.

=cut

sub create_group { 0 }

=head2 $plugin-E<gt>delete_group( $group )

Delete the given group.

=cut

sub delete_group { 0 }

=head2 $plugin-E<gt>grant( $group, $action, $resource )

Grant the given group or user the authorization to perform the given
$action on the given $resource.

=cut

sub grant { 0 }

=head2 $plugin-E<gt>update_group( $group, $users )

Update the given group, setting the set of users that belong to that
group.  The existing group membership will be replaced with the new one.
$users is a comma separated list of user names.

=cut

sub update_group { 0 }

1;
