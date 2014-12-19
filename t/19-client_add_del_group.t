use strict;
use warnings;
use 5.010001;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

$ENV{LOG_LEVEL} = 'FATAL';

$PlugAuth::VERSION = '0.01';

BEGIN {
  my $min_version = '0.12';
  plan skip_all => 'requires PlugAuth::Client' 
    # fake it if the PlugAuth::Client dist is checkout as a sibling
    unless eval q{
      use lib "$FindBin::Bin/../../PlugAuth-Client/lib";
      use PlugAuth::Client;
      1;
    }
    # test only works if PlugAuth::Client is installed
    ||     eval qq{ use PlugAuth::Client $min_version; 1 };
  plan tests => 13;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = eval { $t->ua->server->url->port } // $t->ua->app_url->port;
  my $client = PlugAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'PlugAuth::Client';
$client->login('primus', 'primus');

# First check that the groups are right at start.
eq_or_diff [sort @{ $client->users('full1')}], [sort qw( foo bar baz primus )], "at start full1 = foo bar baz";
eq_or_diff [sort @{ $client->users('full2')}], [sort qw( foo bar baz primus )], "at start full2 = foo bar baz";
eq_or_diff [sort @{ $client->users('part1')}], [sort qw( foo )], "at start part1 = foo";
eq_or_diff [sort @{ $client->users('part2')}], [sort qw( baz )], "at start part2 = baz";

# next add bar to part1
eval { $client->group_add_user('part1', 'bar') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('part1') }], [sort qw( foo bar) ], "at start part1 = foo bar";

# next add to a non-existent group
is eval { $client->group_add_user('bogus', 'bar') }, undef, 'add to non existent group';
diag $@ if $@;
is $client->users('bogus'), undef, "add to non existent group doesn't create group";

# add bar and baz to part2
eval { $client->group_add_user('part2', 'bar') };
diag $@ if $@;
eval { $client->group_add_user('part2', 'foo') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('part2') }], [sort qw( foo bar baz) ], "part2 = foo bar baz";

# add foo to full1 and full2
eval { $client->group_add_user('full1', 'bar') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('full1') }], [sort qw( foo bar baz primus) ], "at start full1 = foo bar baz primus";
eval { $client->group_add_user('full2', 'bar') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('full2') }], [sort qw( foo bar baz primus) ], "at start full2 = foo bar baz primus";

# remove foo from full3 and full4
eval { $client->group_delete_user('full3', 'foo') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('full3') }], [sort qw( bar baz primus) ], "at start full3 = foo bar baz primus";
eval { $client->group_delete_user('full4', 'foo') };
diag $@ if $@;
eq_or_diff [sort @{ $client->users('full4') }], [sort qw( bar baz primus) ], "at start full4 = foo bar baz primus";
