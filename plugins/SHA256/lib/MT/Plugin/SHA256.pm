package MT::Plugin::SHA256;
use strict;
use warnings;

my $Debug = 0;

use Digest::SHA::PurePerl;

sub init_app {
    require MT::Auth::MT;
    require MT::Author;
    require MT::BasicAuthor;

    my $is_valid_password = \&MT::Auth::MT::is_valid_password;

    no warnings 'once';
    *MT::Auth::MT::is_valid_password = sub {
        my ( $auth, $author, $pass, $crypted, $error_ref ) = @_;

        my $result    = $is_valid_password->(@_);
        my $real_pass = $author->column('password');

        if ($result) {
            if ( $real_pass && $real_pass =~ /^{SHA}/ ) {
                $author->set_password($pass);
                $author->save or die;
            }
            return $result;
        }
        else {
            return $result unless $real_pass;

            if ( $real_pass =~ /^{SHA2}(.+)\$(.+)/ ) {
                my ( $salt, $value ) = ( $1, $2 );
                return $value eq
                    Digest::SHA::PurePerl::sha256_base64( $salt . $pass )
                    || $result;
            }
        }
    };

    *MT::Author::set_password = *MT::BasicAuthor::set_password = sub {
        my $auth   = shift;
        my ($pass) = @_;
        my @alpha  = ( 'a' .. 'z', 'A' .. 'Z', 0 .. 9 );
        my $salt   = join '', map $alpha[ rand @alpha ], 1 .. 16;
        my $crypt_sha;

        if ( !$Debug || eval { require Digest::SHA } ) {

            # Can use SHA512
            $crypt_sha
                = '$6$'
                . $salt . '$'
                . Digest::SHA::sha512_base64( $salt . $pass );
        }
        else {

            # Use SHA256
            $crypt_sha
                = '{SHA2}'
                . $salt . '$'
                . Digest::SHA::PurePerl::sha256_base64( $salt . $pass );
        }

        $auth->column( 'password', $crypt_sha );
    };
}

1;
