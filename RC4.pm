#--------------------------------------------------------------------#
# Crypt::RC4
#       Date Written:   07-Jun-2000 04:15:55 PM
#       Last Modified:  23-Nov-2001 01:20:31 PM
#       Author:         Kurt Kincaid (sifukurt@yahoo.com)
#       Copyright (c) 2001, Kurt Kincaid
#       	All Rights Reserved.
#
#       This is free software and may be modified and/or
#       redistributed under the same terms as Perl itself.
#--------------------------------------------------------------------#

package Crypt::RC4;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(RC4);
$VERSION = '2.0';

our ( $class, $key, @k, @s );

sub new {
    ( $class, $key )  = @_;
    my $self = bless {}, $class;
	Setup( $key );
    return $self;
}

sub RC4 {
	my ( $x, $y, $z );
	if ( ref $_[0] ) {
		my $self = shift;
	} else {
		Setup( shift );
	}
	for ( unpack( 'C*', shift ) ) {
		$x = ($x + 1) % 256;
		$y = ( $s[$x] + $y ) % 256;
		@s[$x, $y] = @s[$y, $x];
		$z .= pack ( 'C', $_ ^= $s[( $s[$x] + $s[$y] ) % 256] );
	}
	return $z;
}

sub Setup {
    my ( $x, $y );
	@k = unpack( 'C*', shift );
	@s = 0..255;
	for ($x = 0; $x != 256; $x++) {
		$y = ( $k[$x % @k] + $s[$x] + $y ) % 256;
		@s[$x, $y] = @s[$y, $x];
	}
}


1;
__END__

=head1 NAME

Crypt::RC4 - Perl implementation of the RC4 encryption algorithm

=head1 SYNOPSIS

# Functional Style

  use Crypt::RC4;
  $encrypted = RC4( $passphrase, $plaintext );
  $decrypt = RC4( $passphrase, $encrypted );
  
# OO Style
  use Crypt::RC4;
  $ref = Crypt::RC4->new( $passphrase );
  $encrypted = $ref->RC4( $plaintext );
  
  $ref2 = Crypt::RC4->new( $passphrase );
  $decrypted = $ref->RC4( $encrypted );

=head1 DESCRIPTION

A simple implementation of the RC4 algorithm, developed by RSA Security, Inc. Here is the description
from RSA's website:

RC4 is a stream cipher designed by Rivest for RSA Data Security (now RSA Security). It is a variable
key-size stream cipher with byte-oriented operations. The algorithm is based on the use of a random
permutation. Analysis shows that the period of the cipher is overwhelmingly likely to be greater than
10100. Eight to sixteen machine operations are required per output byte, and the cipher can be
expected to run very quickly in software. Independent analysts have scrutinized the algorithm and it
is considered secure.

Based substantially on the "RC4 in 3 lines of perl" found at http://www.cypherspace.org

A major bug in v1.0 was fixed by David Hook (dgh@wumpus.com.au).  Thanks, David.

=head1 AUTHOR

Kurt Kincaid (sifukurt@yahoo.com)
Ronald Rivest for RSA Security, Inc.
David Hook (dgh@wumpus.com.au)

=head1 SEE ALSO

L<perl>, L<http://www.cypherspace.org>, L<http://www.rsasecurity.com>

=cut
