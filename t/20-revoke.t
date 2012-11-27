use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 475;
use Test::Mojo;
use Mojo::JSON;
use Test::Differences;

my $t = Test::Mojo->new('PlugAuth');
$t->get_ok('/'); # creates $t->ua
my $port = $t->ua->app_url->port;

# /authz/user/#user/#action/(*resource)
# optimus:mpmPbOhUeIt1E
# primus:Bv4QLfsRAW.pY
# grimlock:uogf5/viZOdDA
# starscream:tCp3KDOivhlzo
# megatron:8n2eh8qdddqdI
# skylynks:wPCaIh1gAmL8w
# swoop:G/LxEEIR9PsBI
# unicron:g8qCjd1FUZUEk

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(200)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(200)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(200)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/megatron/retreat/battle")->status_is(200);
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/optimus/open/matrix")->status_is(200);
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( megatron grimlock starscream skylynks swoop primus unicron );
};

$t->delete_ok("/grant/megatron/open/matrix")->status_is(401);
$t->delete_ok("/grant/optimus/open/matrix")->status_is(401);
$t->delete_ok("http://primus:foo\@localhost:$port/grant/megatron/open/matrix")
  ->status_is(404)->content_is('not ok');
$t->delete_ok("http://primus:foo\@localhost:$port/grant/optimus/open/matrix")
  ->status_is(200)->content_is('ok');

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(200)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(200)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(200)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/megatron/retreat/battle")->status_is(200);
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( optimus megatron grimlock starscream skylynks swoop primus unicron );
};

$t->delete_ok("http://primus:foo\@localhost:$port/grant/megatron/retreat/battle")->status_is(200);

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(200)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(200)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(200)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( megatron optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( optimus megatron grimlock starscream skylynks swoop primus unicron );
};

$t->delete_ok("http://primus:foo\@localhost:$port/grant/autobot/color/red")->status_is(200);

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(200)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(403)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(200)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( megatron optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( optimus megatron grimlock starscream skylynks swoop primus unicron );
};

$t->delete_ok("http://primus:foo\@localhost:$port/grant/decepticon/color/purple")->status_is(200);

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(200)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(403)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(403)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( megatron optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( optimus megatron grimlock starscream skylynks swoop primus unicron );
};

$t->delete_ok("http://primus:foo\@localhost:$port/grant/public/transform/altmode")->status_is(200);

do {
  # / (accounts): god
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop );
  $t->get_ok("/authz/user/$_/accounts/user")->status_is(200)
    for qw( primus unicron );

  # /altmode (transform): public
  $t->get_ok("/authz/user/$_/transform/altmode")->status_is(403)
    for qw( optimus grimlock starscream megatron skylynks swoop primus unicron );

  # /red (color): autobot
  # /purple (color): decepticon
  $t->get_ok("/authz/user/$_/color/red")->status_is(403)
    for qw( optimus grimlock skylynks swoop );
  $t->get_ok("/authz/user/$_/color/purple")->status_is(403)
    for qw( starscream megatron );
    
  # /battle (retreat): megatron
  $t->get_ok("/authz/user/$_/retreat/battle")->status_is(403)
    for qw( megatron optimus grimlock starscream skylynks swoop primus unicron );

  # /matrix (open): optimus
  $t->get_ok("/authz/user/$_/open/matrix")->status_is(403)
    for qw( optimus megatron grimlock starscream skylynks swoop primus unicron );
};