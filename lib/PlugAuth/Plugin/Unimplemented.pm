package PlugAuth::Plugin::Unimplemented;

use strict;
use warnings;
use Role::Tiny::With;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Authz';
with 'PlugAuth::Role::Admin';

# ABSTRACT: PlugAuth plugin that doesn't implement anything
# VERSION

=head1 SYNOPSIS

PlugAuth.conf:

 ---
 plugins:
   - PlugAuth::Plugin::Unimplemented

=head1 DESCRIPTION

Returns 404 for all methods that this plugin handles.
Typically you wouldn't use this plugin directly, it
is instead intended as a place holder when you specify
an L<Authz|PlugAuth::Role::Authz> plugin, but no
L<Admin|PlugAuth::Role::Admin> plugin.

=cut


sub check_credentials {}
sub all_users {}
sub can_user_action_resource {}
sub match_resources {}
sub host_has_tag {}
sub actions {}
sub groups {}
sub all_groups {}
sub users {}
sub create_user {}
sub change_password {} 
sub delete_user {} 
sub create_group {}
sub delete_group {}
sub grant {}

1;
