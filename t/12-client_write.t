use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

BEGIN {
  my $min_version = '0.09';
  plan skip_all => 'requires PlugAuth::Client' 
    # fake it if the PlugAuth::Client dist is checkout as a sibling
    unless eval q{
      use lib "$FindBin::Bin/../../PlugAuth-Client/lib";
      use PlugAuth::Client;
      1;
    }
    # test only works if PlugAuth::Client is installed
    ||     eval qq{ use PlugAuth::Client $min_version; 1 };
  plan tests => 25;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = $t->ua->app_url->port;
  my $client = PlugAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'PlugAuth::Client';

$client->login('primus', 'cybertron');
eq_or_diff [grep /^thrust$/, @{ $client->user }], [], 'user thrust does not exist';
ok $client->create_user(user => 'thrust', password => 'foo'), 'client.create_user(user: thrust, password: foo)';
eq_or_diff [grep /^thrust$/, @{ $client->user }], ['thrust'], 'user thrust was created';

eq_or_diff [grep /^wheelie$/, @{ $client->user }], ['wheelie'], 'user wheelie does exist';
ok $client->delete_user('wheelie'), 'client.delete_user(wheelie)';
eq_or_diff [grep /^wheelie$/, @{ $client->user }], [], 'user wheelie has been deleted';

eq_or_diff [grep /^seekers$/, @{ $client->group }], [], 'group seekers does not exist yet';
ok $client->create_group(group => 'seekers', users => 'starscream,thundercracker,skywarp,thrust,ramjet,dirge'), 'client.create_group(group: seekers, ...)';
eq_or_diff [grep /^seekers$/, @{ $client->group }], ['seekers'], 'group seekers has been created';
eq_or_diff [sort @{ $client->users('seekers') }], [sort qw( starscream thundercracker skywarp thrust ramjet dirge )], 'check seeker membership';

eq_or_diff [sort @{ $client->users('primes') }], ['optimus'], 'primes includes just optimus';
ok $client->update_group('primes', '--users' => 'optimus,rodimus'), 'add rodimus to the list of primes';
eq_or_diff [sort @{ $client->users('primes') }], [sort qw( optimus rodimus )], 'primes includes just optimus';

eq_or_diff [grep /^primes$/, @{ $client->group }], ['primes'], 'group primes does exist';
ok $client->delete_group('primes'), 'client.delete(primes)';
eq_or_diff [grep /^primes$/, @{ $client->group }], [], 'group primes has been deleted';

eq_or_diff [grep /^open$/, @{ $client->actions }], [], 'no such action yet, open';
ok $client->grant('optimus', 'open', 'matrix'), 'client.grant(optimus, open, matrix)';
eq_or_diff [grep /^open$/, @{ $client->actions }], ['open'], 'no such action yet, open';

eq_or_diff [sort @{ $client->users('cars') }], [sort qw( kup hotrod )], 'cars group = kup and hotrod';
ok $client->update_group('cars', { users => 'kup,hotrod,blurr' }), 'client.update_group(cars, ...)';
eq_or_diff [sort @{ $client->users('cars') }], [sort qw( kup hotrod blurr )], 'cars group = kup, hotrod and blurr';

is $client->resources('primus', 'accounts', '/')->[0], '/', 'client.resource 1';
is $client->resources('optimus', 'open', '/')->[0], '/matrix', 'client.resource 2';
