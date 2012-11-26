package Test::PlugAuth::Plugin::Authz;

use strict;
use warnings;
use v5.10;
use Test::Builder;
use Role::Tiny ();
use PlugAuth;
use base qw( Exporter );

our @EXPORT = qw( run_tests );

# FIXME: finish this test

# ABSTRACT: Test a PlugAuth Authz plugin for correctness
# VERSION

=head1 SYNOPSIS

 use Test::PlugAuth::Plugin::Authz;
 run_tests 'MyPlugin';  # runs tests against PlugAuth::Plugin::MyPlugin

=head1 FUNCTIONS

=head2 run_tests $plugin_name, [ $global_config, [ $plugin_config ] ]

Run the specification tests against the given plugin.  The configuraton
arguments are optional.  The first is the hash which is usually found in
~/etc/PlugAuth.conf and the second is the plugin config.

=cut

my $Test = Test::Builder->new;

sub run_tests
{
  my($class, $global_config, $plugin_config) = @_;
  $class = "PlugAuth::Plugin::$class" unless $class =~ /::/;
  eval qq{ use $class };
  die $@ if $@;
  
  $global_config //= {};
  $global_config = Clustericious::Config->new($global_config)
    unless eval { $global_config->isa('Clustericious::Config') };
  $plugin_config //= {};
  
  $Test->plan( tests => 3);
  
  my $object = eval { $class->new($global_config, $plugin_config, PlugAuth->new()) };
  my $error = $@;
  if(ref $object)
  {
    $Test->ok(1, "New returns a reference");
  }
  else
  {
    $Test->ok(0, "New returns a reference");
    $Test->diag("ERROR: $error");
  }
  
  $Test->ok( Role::Tiny::does_role($object, 'PlugAuth::Role::Plugin'),  'does Plugin');
  $Test->ok( Role::Tiny::does_role($object, 'PlugAuth::Role::Authz'), 'does Auth');
}

1;

=head1 SEE ALSO

L<PlugAuth>,
L<PlugAuth::Guide::Plugin>

=cut
