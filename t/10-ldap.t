use strict;
use warnings;
use FindBin ();
BEGIN { require "$FindBin::Bin/etc/setup.pl" }
use Test::More tests => 15;
use Test::Mojo;

my $t = Test::Mojo->new('PlugAuth');

my $port = $t->ua->app_url->port;

my $net_ldap_saw_user;
my $net_ldap_saw_password;

# good user, good password
$t->get_ok("http://optimus:matrix\@localhost:$port/auth")
  ->status_is(200)
  ->content_is("ok", 'auth succeeded');

is $net_ldap_saw_user, 'optimus', 'user = optimus';
is $net_ldap_saw_password, 'matrix', 'password = matrix';

# good user, bad password
$t->get_ok("http://optimus:badguess\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth succeeded');

is $net_ldap_saw_user, 'optimus', 'user = optimus';
is $net_ldap_saw_password, 'badguess', 'password = badguess';

# good user, bad password
$t->get_ok("http://bogus:matrix\@localhost:$port/auth")
  ->status_is(403)
  ->content_is("not ok", 'auth succeeded');

is $net_ldap_saw_user, 'bogus', 'user = bogus';
is $net_ldap_saw_password, 'matrix', 'password = matrix';

package Net::LDAP;

BEGIN { $INC{'Net/LDAP.pm'} = __FILE__ }

sub new
{
  bless {}, 'Net::LDAP';
}

sub bind
{
  my($self, $dn, %args) = @_;

  if($dn =~ /^uid=([a-z]+), ou=people, dc=users, dc=eosdis, dc=nasa, dc=gov$/)
  { $net_ldap_saw_user = $1 }
  else
  { $net_ldap_saw_user = '---' }
  $net_ldap_saw_password = $args{password};

  my $code = !($net_ldap_saw_user eq 'optimus' && $net_ldap_saw_password eq 'matrix');
  bless { code => $code }, 'Net::LDAP::Message';
}


package Net::LDAP::Message;

sub code { shift->{code} }
sub error { shift->{code} ? 'unauthorized' : 'authorized' }
