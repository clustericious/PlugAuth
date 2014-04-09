
use strict;
use warnings;

use 5.010000;

use ExtUtils::MakeMaker 6.30;



my %WriteMakefileArgs = (
  "ABSTRACT" => "Pluggable authentication and authorization server.",
  "AUTHOR" => "Graham Ollis <gollis\@sesda3.com>",
  "BUILD_REQUIRES" => {},
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
    "Clustericious" => "0.9936",
    "Clustericious::Config" => "0.25",
    "Clustericious::Log" => "0.14",
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
    "Role::Tiny" => 0,
    "Test::Builder" => 0,
    "Text::Glob" => 0,
    "YAML::XS" => 0,
    "autodie" => 0
  },
  "TEST_REQUIRES" => {
    "File::HomeDir" => 0,
    "Test::Clustericious::Cluster" => "0.08",
    "Test::Clustericious::Config" => 0,
    "Test::Clustericious::Log" => 0,
    "Test::Differences" => 0,
    "Test::More" => 0
  },
  "VERSION" => "0.26",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


my %FallbackPrereqs = (
  "Class::Method::Modifiers" => 0,
  "Clone" => 0,
  "Clustericious" => "0.9936",
  "Clustericious::Config" => "0.25",
  "Clustericious::Log" => "0.14",
  "Crypt::PasswdMD5" => 0,
  "Exporter" => 0,
  "Fcntl" => 0,
  "File::HomeDir" => 0,
  "File::HomeDir::Test" => 0,
  "File::Spec" => 0,
  "File::Temp" => 0,
  "File::Touch" => 0,
  "File::stat" => 0,
  "FindBin" => 0,
  "IO::File" => 0,
  "List::MoreUtils" => 0,
  "Log::Log4perl" => 0,
  "Role::Tiny" => 0,
  "Test::Builder" => 0,
  "Test::Clustericious::Cluster" => "0.08",
  "Test::Clustericious::Config" => 0,
  "Test::Clustericious::Log" => 0,
  "Test::Differences" => 0,
  "Test::More" => 0,
  "Text::Glob" => 0,
  "YAML::XS" => 0,
  "autodie" => 0
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.63_03) } ) {
  delete $WriteMakefileArgs{TEST_REQUIRES};
  delete $WriteMakefileArgs{BUILD_REQUIRES};
  $WriteMakefileArgs{PREREQ_PM} = \%FallbackPrereqs;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



