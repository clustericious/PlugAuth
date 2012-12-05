package PlugAuth::Role::Welcome;

use strict;
use warnings;
use Role::Tiny;

# ABSTRACT: Role for PlugAuth reload plugins
# VERSION

=head1 SYNOPSIS

 package PlugAuth::Plugin::MyRefresh;
 
 use Role::Tiny::With;
 
 with 'PlugAuth::Role::Plugin';
 with 'PlugAuth::Role::Welcome';
 
 sub welcome {
   my ($self, $c) = @_;
   # called on GET / requests
 }
 
 1;

=head1 DESCRIPTION

Use this role for PlugAuth plugins which provide alternate functionality
for the default GET / route.

=head1 REQUIRED ABSTRACT METHODS

=head2 $plugin-E<gt>welcome( $controller )

Called on GET / routes

=cut

requires qw( welcome );

1;

=head1 SEE ALSO

L<PlugAuth>,
L<PlugAuth::Guide::Plugin>,

=cut