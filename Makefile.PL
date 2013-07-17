
use strict;
use warnings;

use 5.010000;

use ExtUtils::MakeMaker 6.30;



my %WriteMakefileArgs = (
  "ABSTRACT" => "Pluggable authentication and authorization server.",
  "AUTHOR" => "Graham Ollis <gollis\@sesda3.com>",
  "BUILD_REQUIRES" => {
    "File::HomeDir" => 0,
    "Mojo::JSON" => 0,
    "Test::Clustericious::Cluster" => 0,
    "Test::Clustericious::Config" => 0,
    "Test::Differences" => 0,
    "Test::Mojo" => 0,
    "Test::More" => 0
  },
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => "6.30"
  },
  "DISTNAME" => "PlugAuth",
  "EXE_FILES" => [
    "bin/plugauth"
  ],
  "LICENSE" => "perl",
  "NAME" => "PlugAuth",
  "PREREQ_PM" => {
    "Class::Method::Modifiers" => 0,
    "Clone" => 0,
    "Clustericious" => "0.9920",
    "Clustericious::App" => 0,
    "Clustericious::Commands" => 0,
    "Clustericious::Config" => "0.17",
    "Clustericious::Log" => 0,
    "Clustericious::RouteBuilder" => 0,
    "Crypt::PasswdMD5" => 0,
    "Exporter" => 0,
    "Fcntl" => 0,
    "File::HomeDir::Test" => 0,
    "File::Spec" => 0,
    "File::Temp" => 0,
    "File::Touch" => 0,
    "File::stat" => 0,
    "FindBin" => 0,
    "IO::File" => 0,
    "List::MoreUtils" => 0,
    "Log::Log4perl" => 0,
    "Mojo::Base" => 0,
    "Mojo::ByteStream" => 0,
    "Role::Tiny" => 0,
    "Role::Tiny::With" => 0,
    "Test::Builder" => 0,
    "Text::Glob" => 0,
    "YAML::XS" => 0,
    "autodie" => 0
  },
  "VERSION" => "0.20_01",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



