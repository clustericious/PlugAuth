use strict;
use warnings;
use autodie;
use v5.10;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 18;
use Test::Mojo;
use File::HomeDir;
use File::Spec;
use Clustericious::Config;
use YAML ();

do {
  my $config = Clustericious::Config->new('PlugAuth');
  $config->{plugins} = [
    { 'PlugAuth::Plugin::FlatUserList' => { 'user_list_file' => File::Spec->catfile(File::HomeDir->my_home, 'user_list.txt') } },
    { 'PlugAuth::Plugin::FlatAuth' => {} },
  ];
  mkdir(File::Spec->catdir(File::HomeDir->my_home, 'etc'));
  open(my $fh, '>', File::Spec->catfile(File::HomeDir->my_home, 'etc', 'PlugAuth.conf'));
  print $fh $config->dump_as_yaml;
  close $fh;
  $ENV{CLUSTERICIOUS_CONF_DIR} = File::Spec->catdir(File::HomeDir->my_home, 'etc');
  
  open($fh, '>', File::Spec->catfile(File::HomeDir->my_home, 'user_list.txt'));
  say $fh "ralph";
  say $fh "bob";
  say $fh "george";
  say $fh "bar";
  close $fh;
};

my $t = Test::Mojo->new('PlugAuth');
my $port = $t->ua->app_url->port;

isa_ok $t->app->auth, 'PlugAuth::Plugin::FlatUserList';
isa_ok $t->app->auth->next_auth, 'PlugAuth::Plugin::FlatAuth';
is $t->app->auth->next_auth->next_auth, undef, 'app->auth->next_auth->next_auth is undef';

$t->get_ok("http://foo:foo\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

$t->get_ok("http://bar:bar\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth succeeded');
  
$t->get_ok("http://localhost:$port/user")
    ->status_is(200)
    ->json_content_is([sort
        qw( foo bar ralph bob george )
    ], 'full sorted user list');

do {
  open(my $fh, '>>', File::Spec->catfile(File::HomeDir->my_home, 'user_list.txt'));
  print $fh "optimus";
  close $fh;
  # fake it that the mtime is older for test
  $t->app->auth->{mtime} -= 5;
};

$t->get_ok("http://localhost:$port/user")
    ->status_is(200)
    ->json_content_is([sort
        qw( foo bar ralph bob george optimus )
    ], 'full sorted user list');

do {
  open(my $fh, '>', File::Spec->catfile(File::HomeDir->my_home, 'user_list.txt'));
  print $fh "one";
  close $fh;
  # fake it that the mtime is older for test
  $t->app->auth->{mtime} -= 5;
};

$t->get_ok("http://localhost:$port/user")
    ->status_is(200)
    ->json_content_is([sort
        qw( foo bar one )
    ], 'full sorted user list');