package PlugAuth::Role::Refresh;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth reload plugins
# VERSION

=head1 SYNOPSIS

 package PlugAuth::Plugin::MyRefresh;
 
 use Role::Tiny::With;
 
 with 'PlugAuth::Role::Plugin';
 with 'PlugAuth::Role::Refresh';
 
 sub refresh {
   my ($self) = @_;
   # called on every request
 }
 
 1;

=head1 DESCRIPTION

Use this role for PlugAuth plugins which need to be refreshed
on every call.  You will likely want to mix this role in with either
or both L<PlugAuth::Role::Auth> and L<PlugAuth::Role::Authz>.

=head1 REQUIRED ABSTRACT METHODS

=head2 $plugin-E<gt>refresh

Called on every request.

=cut

requires qw( refresh );

1;
