package Crypt::RC4;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw(RC4);
$VERSION = '1.11';

sub RC4 {
	my $x = 0;
	my $y = 0;

	my $key = shift;
	my @k = unpack( 'C*', $key );
	my @s = 0..255;

	for ($x = 0; $x != 256; $x++) {
		$y = ( $k[$x % @k] + $s[$x] + $y ) % 256;
		@s[$x, $y] = @s[$y, $x];
	}

	$x = $y = 0;

	my $z = undef;

	for ( unpack( 'C*', shift ) ) {
		$x = ($x + 1) % 256;
		$y = ( $s[$x] + $y ) % 256;
		@s[$x, $y] = @s[$y, $x];
		$z .= pack ( 'C', $_ ^= $s[( $s[$x] + $s[$y] ) % 256] );
	}

	return $z;
}

1;
__END__

=head1 NAME

Crypt::RC4 - Perl implementation of the RC4 encryption algorithm

=head1 SYNOPSIS

  use Crypt::RC4;
  $encrypted = RC4( $passphrase, $plaintext );
  $decrypt = RC4( $passphrase, $encrypted );

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

perl(1), http://www.cypherspace.org, http://www.rsasecurity.com

=cut
