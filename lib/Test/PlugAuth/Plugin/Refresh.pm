package Test::PlugAuth::Plugin::Refresh;

use strict;
use warnings;
use Test::Builder;
use Role::Tiny ();
use base qw( Exporter );

our @EXPORT = qw( run_tests );

# ABSTRACT: Test a PlugAuth Refresh plugin for correctness
# VERSION

=head1 SYNOPSIS

 use Test::PlugAuth::Plugin::Refresh;
 run_tests 'MyPlugin';  # runs tests against PlugAuth::Plugin::MyPlugin

=head1 FUNCTIONS

=head2 run_tests $plugin_name

Run the specification tests against the given plugin.

=cut

my $Test = Test::Builder->new;

sub run_tests
{
  my($class) = @_;
  $class = "PlugAuth::Plugin::$class" unless $class =~ /::/;
  eval qq{ use $class };
  die $@ if $@;
  
  $Test->plan( tests => 4);
  
  my $object = eval { $class->new };
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
  $Test->ok( Role::Tiny::does_role($object, 'PlugAuth::Role::Refresh'), 'does Refresh');
  $Test->ok( eval { $object->can('refresh') }, "can refresh");
};

1;
