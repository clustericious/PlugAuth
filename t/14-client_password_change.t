use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More;
use Test::Mojo;
use PlugAuth;
use Test::Differences;

$ENV{LOG_LEVEL} = 'FATAL';

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
  plan tests => 4;
}

my $client = do {
  my $t = Test::Mojo->new('PlugAuth');
  my $port = $t->ua->app_url->port;
  my $client = PlugAuth::Client->new(server_url => "http://localhost:$port");
  $client->client($t->ua);
  $client;
};

isa_ok $client, 'PlugAuth::Client';

$client->login('optimus', 'matrix');
ok $client->auth, 'client.login(optimus, matrix); client.auth';

$client->login('primus', 'cybertron');
ok eval { $client->change_password('optimus', 'matrix1') }, 'client.change_password(optimus, matrix1)';
diag $@ if $@;

$client->login('optimus', 'matrix1');
ok $client->auth, 'client.login(optimus, matrix1); client.auth';
