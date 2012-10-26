package PlugAuth::Plugin::LDAP;

# ABSTRACT: LDAP back end for PlugAuth
# VERSION

=head1 SYNOPSIS

Sample LDAP configuration :

 ldap :
   server : ldap://198.118.255.141:389
   dn : uid=%s, ou=people, dc=users, dc=eosdis, dc=nasa, dc=gov
   authoritative : 1

Note that %s in the dn will be replaced with the username
when binding to the LDAP server.

=head1 DESCRIPTION

Handle authentication only from LDAP server.
Everything else is handled by L<PlugAuth::Plugin::FlatFiles>
(e.g. authorization, groups, etc).

=cut

use strict;
use warnings;
use base qw( PlugAuth::Plugin::FlatFiles );
use v5.10;
use Net::LDAP;
use Log::Log4perl qw/:easy/;

our $Ldap;

=head1 METHODS

=head2 PlugAuth::Plugin::LDAP-E<gt>config( [ $config ] )

Set/get the instance of L<Clustericious::Config> to use for configuring
PlugAuth.

=cut

sub config {
    my($class, $new_value) = @_;
    if(defined $new_value) {
        $Ldap = $new_value->ldap(default => '');
    }
    $class->SUPER::config($new_value);
}


=head2 PlugAuth::Plugin::LDAP-E<gt>check_credentials( $user, $password )

Given a user and password, check to see if the password is correct.

=cut

sub check_credentials {
    my ($class, $user,$pw) = @_;
    $user = lc $user;

    if (!$Ldap or !$Ldap->{authoritative}) {
        # Check files first.
        return 1 if $class->SUPER::check_credentials($user, $pw);
    }
    return 0 unless $Ldap;
    my $server = $Ldap->{server} or LOGDIE "Missing ldap server";
    my $ldap = Net::LDAP->new($server, timeout => 5) or do {
        ERROR "Could not connect to ldap server $server: $@";
        return 0;
    };
    my $orig = $user;
    my $extra = $user =~ tr/a-zA-Z0-9@._-//dc;
    WARN "Invalid username '$orig', turned into $user" if $extra;
    my $dn = sprintf($Ldap->{dn},$user);
    my $mesg = $ldap->bind($dn, password => $pw);
    $mesg->code or return 1;
    INFO "Ldap returned ".$mesg->code." : ".$mesg->error;
    return 0;
}

1;

=head1 SEE ALSO

L<PlugAuth>, L<PlugAuth::Routes>, L<PlugAuth::Plugin::FlatFiles>

=cut
