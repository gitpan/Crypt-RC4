# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..4\n"; }
END {print "not ok 1\n" unless $loaded;}
use Crypt::RC4;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

#
# test vectors are from:
#
#        Legion of The Bouncy Castle Java Crypto Libraries http://www.bouncycastle.org
# and    Crypto++ 3.2 http://www.eskimo.com/~weidai/cryptlib.html
#

my $passphrase = pack('C*', (0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef));
my $plaintext = pack('C*', (0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef));
my $encrypted = RC4( $passphrase, $plaintext );
my $decrypt = RC4( $passphrase, $encrypted );

if (($encrypted ne pack('C*', (0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96))) && ($decrypt ne $plaintext))
{
    print "not ok 2\n";
}
else
{
    print "ok 2\n";
}

$passphrase = pack('C*', (0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef));
$plaintext = pack('C*', (0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20));
$encrypted = RC4( $passphrase, $plaintext );
$decrypt = RC4( $passphrase, $encrypted );

if (($encrypted ne pack('C*', (0x1c,0xf1,0xe2,0x93,0x79,0x26,0x6d0x59))) && ($decrypt ne $plaintext))
{
    print "not ok 3\n";
}
else
{
    print "ok 3\n";
}

$passphrase = pack('C*', (0xef,0x01,0x23,0x45));
$plaintext = pack('C*', (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00));
$encrypted = RC4( $passphrase, $plaintext );
$decrypt = RC4( $passphrase, $encrypted );

if (($encrypted ne pack('C*', (0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61))) && ($decrypt ne $plaintext))
{
    print "not ok 4\n";
}
else
{
    print "ok 4\n";
}
