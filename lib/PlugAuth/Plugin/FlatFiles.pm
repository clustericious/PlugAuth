package PlugAuth::Plugin::FlatFiles;

# ABSTRACT: flat file back end for PlugAuth
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
use File::stat qw/stat/;
use Text::Glob qw/match_glob/;
use Fcntl qw/ :flock /;
use Clone qw( clone );
use Crypt::PasswdMD5 qw( unix_md5_crypt apache_md5_crypt );
use Role::Tiny::With;

with 'PlugAuth::Role::Auth';
with 'PlugAuth::Role::Authz';
with 'PlugAuth::Role::Admin';

our $config;              # Instance of Clustericious::Config
our %Userpw;              # Keys are usernames, values are lists of crypted passwords.
our %groupUser;           # $groupUser{$group}{$user} is true iff $user is in $group
our %userGroups;          # $userGroups{$user}{$group} is true iff $user is in $group
our %resourceActionGroup; # $resourceActionGroup{$resource}{$action}{$group} is true iff $group can do $action on $resource
our %actions;             # All defined actions $actions{$action} = 1;
our %hostTag;             # $hostTag{$host}{$tag} is true iff $user has tag $tag
our %MTimes;

=head1 METHODS

=head2 PlugAuth::Plugin::FlatFiles-E<gt>config( [ $config ] )

Set/get the instance of L<Clustericious::Config> to use for configuring
PlugAuth.

=cut

sub config {
    my($class, $new_value) = @_;
    $config = $new_value if defined $new_value;
    $config;
}


=head2 PlugAuth::Plugin::FlatFiles-E<gt>refresh

Refresh the data (checks the files, and re-reads if necessary).

=cut

sub refresh {
    # Should be called with every request.
    my @user_files = $config->user_file;
    if ( grep _has_changed($_), @user_files ) {
        my @users = map +{ PlugAuth::Plugin::FlatFiles->_read_file($_) }, @user_files;
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
        delete $MTimes{ $config->group_file };
    }
    if ( _has_changed( $config->group_file ) ) {
        %groupUser = ();
        my %data = PlugAuth::Plugin::FlatFiles->_read_file( $config->group_file, nest => 1 );
        for my $k (keys %data) {
            my %users;
            for my $v (keys %{ $data{$k} }) {
               my @matches = match_glob( $v, keys %Userpw );
               next unless @matches;
               @users{ @matches } = (1) x @matches;
            }
            $groupUser{$k} = \%users;
        }
        %userGroups = __PACKAGE__->_reverse_nest(%groupUser);
    }
    if ( _has_changed( $config->resource_file ) ) {
        %resourceActionGroup = __PACKAGE__->_read_file( $config->resource_file, nest => 2 );

        foreach my $resource (keys %resourceActionGroup)
        {
            # TODO: maybe #g for group
            if($resource =~ /#u/) {
                my $value = delete $resourceActionGroup{$resource};

                foreach my $user (__PACKAGE__->all_users) {
                    my $new_resource = $resource;
                    my $new_value = clone $value;

                    $new_resource =~ s/#u/$user/g;

                    foreach my $users (values %$new_value) {
                        if(defined $users->{'#u'}) {
                            delete $users->{'#u'};
                            $users->{$user} = 1;
                        }
                    }

                    $resourceActionGroup{$new_resource} = $new_value;
                }
            }
        }

        %actions = map { map { $_ => 1} keys %$_ } values %resourceActionGroup;
    }
    my $h = $config->host_file(default => '');
    if ( ( $h ) && _has_changed( $h ) ) {
        %hostTag = __PACKAGE__->_read_file( $h, nest => 1 );
    }
    1;
}

sub _has_changed {
    my $filename = shift;
    -e $filename or LOGDIE "File $filename does not exist";
    my $mtime = stat($filename)->mtime;
    return 0 if $MTimes{$filename} && $MTimes{$filename}==$mtime;
    $MTimes{$filename} = $mtime;
    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>check_credentials( $user, $password )

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
    return 0;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>can_user_action_resource( $user, $action, $resource )

If $user can perform $action on $resource, return a string containing
the group and resource that permits this.  Otherwise, return false.

=cut

sub can_user_action_resource {
    my ($class, $user,$action,$resource) = @_;
    $user = lc $user;
    my $found;
    GROUP:
    for my $group ( $user, keys %{ $userGroups{$user} } ) {
        # check exact match on the resource so / will match
        if($resourceActionGroup{$resource}{$action}{$group}) {
            $found = "group: $group resource: $resource";
            last GROUP;
        }
        for my $subresource (__PACKAGE__->_prefixes($resource)) {
            next unless $resourceActionGroup{$subresource}{$action}{$group};
            $found = "group: $group resource: $subresource";
            last GROUP;
        }
    }
    return $found;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>match_resources( $regex )

Given a regex, return all resources that match that regex.

=cut

sub match_resources {
    my($class, $resourceregex) = @_;
    return (grep /$resourceregex/, keys %resourceActionGroup);
}

sub _read_file { # TODO: cache w/ mtime
    my $class = shift;
    my $filename = shift;
    my %args = @_;
    $args{nest} ||= 0;
    #
    # _read_file:
    #  x : y
    #  z : q
    # returns ( x => y, z => q )
    #
    # _read_file(nest => 1):
    #  a : b,c
    #  d : e,f
    # returns ( x => { b => 1, c => 1 },
    #           d => { e => 1, f => 1 } )
    #
    # _read_file(nest => 2):
    #  a : (b) c,d
    #  a : (g) h,i
    #  d : (e) f,g
    # returns ( a => { b => { c => 1, d => 1 },
    #                { g => { h => 1, i => 1 },
    #           d => { e => { f => 1, g => 1 } );
    # Lines beginning with a # are ignored.
    # All spaces are silently squashed.
    #
    TRACE "reading $filename";
    my %h;
    my $fh = IO::File->new("<$filename");
    flock($fh, LOCK_SH) or WARN "Cannot lock $filename - $!\n";
    for my $line ($fh->getlines) {
        chomp $line;
        $line =~ s/\s//g;
        next if $line =~ /^#/ || !length($line);
        my ($k,$v) = split /:/, $line;
        my $p;
        TRACE "parsing $v";
        ($k,$p) = ( $k =~ m/^(.*)\(([^)]*)\)$/) if $args{nest}==2;
        my %m = ( map { $_ => 1 } split /,/, $v ) if $args{nest};
        if ($args{nest}==0) {
            $h{$k} = $v;
        } elsif ($args{nest}==1) {
            $h{$k} ||= {};
            @{ $h{$k} }{keys %m} = values %m;
        } elsif ($args{nest}==2) {
            $h{$k} ||= {};
            $h{$k}{$p} ||= {};
            @{ $h{$k}{$p} }{keys %m} = values %m;
        }
    }
    return %h;
}

sub _reverse_nest {
    my $class = shift;
    # Given a nested hash ( a => b => c), return one with (b => a => c);
    my %h = @_;
    my %new;
    while (my ($a,$bc) = each %h) {
        while (my ($b,$c) = each %$bc) {
            $new{$b}{$a} = $c;
        }
    }
    return %new;
}

sub _prefixes {
    my $class = shift;
    # Given a string "/a/b/c/d" return an array of prefixes :
    #  "/", "/a", "/a/b", /a/b/c", "/a/b/c/d"
    my $str = shift;
    my @p = split /\//, $str;
    my @prefixes = ( map { '/'. join '/', @p[1..$_] } 0..$#p );
    return @prefixes;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>host_has_tag( $host, $tag )

Returns true iof the given host has the given tag.

=cut

sub host_has_tag {
    my ($class, $host, $tag) = @_;
    return exists($hostTag{$host}{$tag});
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>actions

Returns a list of actions.

=cut

sub actions {
    return sort keys %actions;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>groups( $user )

Returns the groups the given user belongs to.

=cut

sub groups {
    my $class = shift;
    my $user = shift or return ();
    $user = lc $user;
    return () unless $Userpw{$user};
    return sort ( $user, keys %{ $userGroups{ $user } || {} } );
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>all_users

Returns a list of all users.

=cut

sub all_users {
    return sort keys %Userpw;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>all_groups

Returns a list of all groups.

=cut

sub all_groups {
    return sort keys %groupUser;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>users( $group )

Return the list of users that belong to the given group.
Each user belongs to a special group that is the same
as their user name and just contains themselves, and
this will be included in the list.

=cut

sub users {
    my $class = shift;
    my $group = shift or return ();
    return () unless defined $groupUser{$group};
    return sort keys %{ $groupUser{$group} };
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>create_user( $user, $password )

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

    foreach my $filename ($config->user_file) {
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
            delete $MTimes{$filename};
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

=head2 PlugAuth::Plugin::FlatFiles-E<gt>change_password( $user, $password )


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

    foreach my $filename ($config->user_file) {
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
        delete $MTimes{$filename};
    }

    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>delete_user( $user )

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

    foreach my $filename ($config->user_file) {
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
        delete $MTimes{$filename};
    }

    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>create_group( $group, $users )

Create a new group with the given users.  $users is a comma
separated list of user names.

=cut

sub create_group
{
    my($class, $group, $users) = @_;

    unless(defined $group) {
        WARN "Group not provided";
        return 0;
    }

    if(defined $groupUser{$group}) {
        WARN "Group $group already exists";
        return 0;
    }

    $users = '' unless defined $users;

    my $filename = $config->group_file;

    eval {
        use autodie;

        open my $fh, '>>', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        print $fh "$group : $users\n";

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    delete $MTimes{$filename};
    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>delete_group( $group )

Delete the given group.

=cut

sub delete_group
{
    my($class, $group) = @_;

    unless($group && defined $groupUser{$group}) {
        WARN "Group $group does not exist";
        return 0;
    }

    my $filename = $config->group_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '+<', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        while(<$fh>) {
            my($thisgroup, $password) = split /\s*:/;
            next if $thisgroup eq $group;
            $buffer .= $_;
        }

        seek $fh, 0, 0;
        truncate $fh, 0;
        print $fh $buffer;

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    delete $MTimes{$filename};
    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>update_group( $group, $users )

Update the given group, setting the set of users that belong to that
group.  The existing group membership will be replaced with the new one.
$users is a comma separated list of user names.

=cut

sub update_group
{
    my($class, $group, $users) = @_;

    unless($group && defined $groupUser{$group}) {
        WARN "Group $group does not exist";
        return 0;
    }

    return 1 unless defined $users;

    my $filename = $config->group_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '+<', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        while(<$fh>) {
            my($thisgroup, $password) = split /\s*:/;
            s{:.*$}{: $users} if $thisgroup eq $group;
            $buffer .= $_;
        }

        seek $fh, 0, 0;
        truncate $fh, 0;
        print $fh $buffer;

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    delete $MTimes{$filename};
    return 1;
}

=head2 PlugAuth::Plugin::FlatFiles-E<gt>grant( $group, $action, $resource )

Grant the given group or user the authorization to perform the given
$action on the given $resource.

=cut

sub grant
{
    my($class, $group, $action, $resource) = @_;

    unless($group && (defined $groupUser{$group} || defined $Userpw{$group})) {
        WARN "Group (or user) $group does not exist";
        return 0;
    }

    $resource = '/' . $resource unless $resource =~ /\//;

    if($resourceActionGroup{$resource}->{$action}->{$group})
    {
      WARN "grant already added $group $action $resource";
      return 1;
    }

    my $filename = $config->resource_file;

    eval {
        use autodie;

        my $buffer = '';

        open my $fh, '>>', $filename;

        eval { flock $fh, LOCK_EX };
        WARN "cannot lock $filename - $@" if $@;

        print $fh "$resource ($action) : $group\n";

        close $fh;
    };

    ERROR "modifying file $filename: $@" if $@;
    delete $MTimes{$filename};
    return 1;
}

1;

=head1 SEE ALSO

L<PlugAuth>, L<PlugAuth::Routes>

=cut
