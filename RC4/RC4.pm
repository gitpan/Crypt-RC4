package Crypt::RC4;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw(RC4);
$VERSION = '1.0';

my @s;
my $x;
my $y;

sub Passphrase {
	my $phrase = shift;
	$phrase =~ s/./ord($&)/eg;
	return sprintf( "%x", $phrase );
}

sub RC4 {
	my $key = shift;
	$key = Passphrase( $key );
	my @k = ();
	my @t = ();
	my @s = ();
	my ($x, $y, $z ) = undef;
	@k = unpack( 'C*', pack( 'H*', $key ) );
	for ( @t=@s=0..255 ) {
		$y = ( $k[$_%@k] + $s[$x=$_] + $y ) % 256;
		&S
	}
	$x = $y = 0;

	for ( unpack( 'C*', shift ) ) {
		$x++;
		$y = ( $s[$x%=256] + $y ) % 256;
		&S;
		$z .= pack ( C, $_^=$s[( $s[$x] + $s[$y] ) % 256] );
	}
	return $z;
}

sub S{
	@s[$x,$y] = @s[$y,$x];
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

=head1 AUTHOR

Ronald Rivest for RSA Security, Inc.
Kurt Kincaid (ceo@neurogames.com)

=head1 SEE ALSO

perl(1), http://www.cypherspace.org, http://www.rsasecurity.com

=cut
