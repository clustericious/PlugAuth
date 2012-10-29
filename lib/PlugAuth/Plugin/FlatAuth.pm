package PlugAuth::Plugin::FlatAuth;

# ABSTRACT: Authentication using Flat Files for PlugAuth
# VERSION

=head1 DESCRIPTION

Manage the data for a simpleauth server.

The interfce is primarily intended for use by
L<PlugAuth::Routes> and is subject to change
without notice, but is documented here.

=cut

use strict;
use warnings;
use v5.10;
use Log::Log4perl qw/:easy/;
use Text::Glob qw/match_glob/;
use Fcntl qw/ :flock /;
use Clone qw( clone );
use Crypt::PasswdMD5 qw( unix_md5_crypt apache_md5_crypt );
use Role::Tiny::With;

with 'PlugAuth::Role::Plugin';
with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Refresh';
with 'PlugAuth::Role::Flat';

our %Userpw;              # Keys are usernames, values are lists of crypted passwords.

=head1 METHODS

=head2 PlugAuth::Plugin::FlatAuth-E<gt>refresh

Refresh the data (checks the files, and re-reads if necessary).

=cut

sub refresh {
    # Should be called with every request.
    my $config = __PACKAGE__->global_config;
    my @user_files = $config->user_file;
    if ( grep has_changed($_), @user_files ) {
        my @users = map +{ __PACKAGE__->read_file($_) }, @user_files;
        %Userpw = ();
        for my $list (@users) {
            for my $user (map { lc $_ } keys %$list) {
                $Userpw{$user} //= [];
                push @{ $Userpw{$user} }, $list->{$user};
            }
        }

        # if the user file has changed, then that may mean the
        # group file has to be reloaded, for example, for groups
        # with wildcards * need to be updated.
        mark_changed($config->group_file);
    }
}

=head2 PlugAuth::Plugin::FlatAuth-E<gt>check_credentials( $user, $password )

Given a user and password, check to see if the password is correct.

=cut

sub _validate_pw
{
    my($plain, $encrypted) = @_;
    return 1 if crypt($plain, $encrypted) eq $encrypted;
    
    # idea borrowed from Authen::Simple::Password
    if($encrypted =~ /^\$(\w+)\$/) {
        return 1 if $1 eq 'apr1' && apache_md5_crypt( $plain, $encrypted ) eq $encrypted;

        # on at least modern Linux crypt will accept a UNIX 
        # MD5 password, so this may be redundant
        return 1 if $1 eq '1'    && unix_md5_crypt  ( $plain, $encrypted ) eq $encrypted;
    }
    return 0;
}

sub check_credentials {
    my ($class, $user,$pw) = @_;
    $user = lc $user;

    if($pw && $Userpw{$user})
    {
      return 1 if grep { _validate_pw($pw, $_) } @{ $Userpw{$user} };
    }
    return $class->deligate_check_credentials($user, $pw);
}

=head2 PlugAuth::Plugin::FlatAuth-E<gt>all_users

Returns a list of all users.

=cut

sub all_users {
    return sort keys %Userpw;
}

=head2 PlugAuth::Plugin::FlatAuth-E<gt>create_user( $user, $password )

Create a new user with the given password.

=cut

sub _created_encrypted_password
{
    my($plain) = @_;
    my $salt = join '', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64];
    apache_md5_crypt($plain, $salt);
}

sub create_user
{
    my($class, $user, $password) = @_;

    unless($user && $password) {
        WARN "User or password not provided";
        return 0;
    }

    $user = lc $user;

    if(defined $Userpw{$user}) {
        WARN "User $user already exists";
        return 0;
    }

    foreach my $filename ($class->global_config->user_file) {
        next unless -w $filename;

        $password = _created_encrypted_password($password);

        eval {
            use autodie;

            open my $fh, '>>', $filename;

            eval { flock $fh, LOCK_EX };
            WARN "cannot lock $filename - $@" if $@;

            print $fh join(':', $user, $password), "\n";

            close $fh;

            # if the file is created in the same second
            # as it is modified, then refresh might
            # not pick up the change, unless we delete
            # the timestatmp.
            mark_changed($filename);
        };

        if($@) {
            WARN "writing file $filename: $@";
            return 0;
        } else {
            return 1;
        }
    }

    ERROR "None of the user files were writable";
    return 0;
}

=head2 PlugAuth::Plugin::FlatAuth-E<gt>change_password( $user, $password )


Change the password of the given user.

=cut

sub change_password
{
    my($class, $user, $password) = @_;

    unless($user && $password) {
        WARN "User or password not provided";
        return 0;
    }

    $user = lc $user;

    unless(defined $Userpw{$user}) {
        WARN "User $user does not exist";
        return 0;
    }

    $password = _created_encrypted_password($password);

    foreach my $filename ($class->global_config->user_file) {
        eval {
            use autodie;

            my $buffer = '';

            open my $fh, '+<', $filename;

            eval { flock $fh, LOCK_EX };
            WARN "cannot lock $filename - $@" if $@;

            while(<$fh>) {
                my($thisuser, $oldpassword) = split /:/;
                if($thisuser eq $user) {
                    $buffer .= join(':', $user, $password) . "\n";
                } else {
                    $buffer .= $_;
                }
            }

            seek $fh, 0, 0;
            truncate $fh, 0;
            print $fh $buffer;

            close $fh;

        };

        ERROR "modifying file $filename: $@" if $@;

        # if the file is created in the same second
        # as it is modified, then refresh might
        # not pick up the change, unless we delete
        # the timestatmp.
        mark_changed($filename);
    }

    return 1;
}

=head2 PlugAuth::Plugin::FlatAuth-E<gt>delete_user( $user )

Delete the given user.

=cut

sub delete_user
{
    my($class, $user) = @_;

    $user = lc $user;

    unless(defined $Userpw{$user}) {
        WARN "User $user does not exist";
        return 0;
    }

    foreach my $filename ($class->global_config->user_file) {
        eval {
            use autodie;

            my $buffer = '';

            open my $fh, '+<', $filename;

            eval { flock $fh, LOCK_EX };
            WARN "cannot lock $filename - $@" if $@;

            while(<$fh>) {
                my($thisuser, $password) = split /:/;
                next if $thisuser eq $user;
                $buffer .= $_;
            }

            seek $fh, 0, 0;
            truncate $fh, 0;
            print $fh $buffer;

            close $fh;

        };

        ERROR "modifying file $filename: $@" if $@;

        # if the file is created in the same second
        # as it is modified, then refresh might
        # not pick up the change, unless we delete
        # the timestatmp.
        mark_changed($filename);
    }

    return 1;
}

1;

=head1 SEE ALSO

L<PlugAuth>, L<PlugAuth::Routes>

=cut