#!/usr/bin/perl
#
# Extract the Terminal Services encryption key from lsadump2 output
#

while (<>) {
	last if (/^L\$HYDRAENCKEY_/);
}

while (<>) {
	last if (!/^ /);
	@bytes = split(/ /);
	for ($i = 1; $i <= 16; $i++) {
		$byte = $bytes[$i];
		last if (length($byte) != 2);
		print chr(hex($byte));
	}
}

