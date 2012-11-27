use strict;
use warnings;
use v5.10;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

$ENV{LOG_LEVEL} = 'FATAL';

$PlugAuth::VERSION = '0.01';

BEGIN {
  my $min_version = '0.13';
  plan skip_all => 'requires PlugAuth::Client' 
    # fake it if the PlugAuth::Client dist is checkout as a sibling
    unless eval q{
      use lib "$FindBin::Bin/../../PlugAuth-Client/lib";
      use PlugAuth::Client;
      1;
    }
    # test only works if PlugAuth::Client is installed
    ||     eval qq{ use PlugAuth::Client $min_version; 1 };
  plan tests => 7;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = $t->ua->app_url->port;
  my $client = PlugAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'PlugAuth::Client';
$client->login('primus', 'primus');

is $client->authz('optimus', 'dies', 'alot'), 'ok',   "optimus dies a lot";
is $client->authz('bogus',   'dies', 'alot'), undef,  "bogus does NOT die a lot";

is $client->revoke('optimus', 'dies', 'alot'), 1,  'revoke returns 1';
is $client->revoke('bogus',   'dies', 'alot'), undef, 'revoke returns undef';

is $client->authz('optimus', 'dies', 'alot'), undef,  "optimus dies a lot";
is $client->authz('bogus',   'dies', 'alot'), undef,  "bogus does NOT die a lot";

