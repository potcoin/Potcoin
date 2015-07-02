#!/bin/sh

# Usage: check <repo> <branch> <last commit checked>

function check(){
	output="merge-$1-$2.txt"

	echo "Checking $1..."

	git fetch $1
	git cherry -v master $1/$2 $3 > $output

	echo "Done, check $output"
}

check bitcoin \
	master \
	3b7925eb7d0653ab304786e8e2344af91a6826fb

check litecoin \
	master-0.8 \
	ccd9a1f5f72235244886d108f014d40d2d6c7bd5

echo ""
echo "In the output files, commits prefixed with a + are not yet merged from upstream for some reason."
echo "After checking them update the pointer to were you checked in this script."
echo ""
echo "If you don't include a commit for some reason, explain why at the bottom of this script."


<<NOTMERGED

# Not merged from Litecoin

570f4b03eba23abb3c09045a673105d956103847 Litecoin: Add checkpoints to testnet
f389e65c8dcb1544a023caff33da41c71fe61a80 Add testnet DNS seed from xurious.com
dc4cd268f521ab7ae503692eb2c56f581087ef9f Update Qt 4.8.3 download link
a8f8323fa9b369f8473511f1c2864ddcac997572 Change release-process.md to sign release tags
5a79068b5aeca439fc7ef08846b7b36175c0c600 Update build-osx.md
70313dd1e7518d410dac30db4906aac4846520a7 Litecoin: settxfee label in LTC
06e78495d588c5f7d8cc56b6eb379fc9c46880c5 Litecoin: Checkpoint at block 541794
41fa6245259bb1edc226c9b49b548d23a6627fc1 Litecoin: Upgrade openssl, qt, miniupnpc, zlib, libpng, qrencode
6ce2f0b2fb4d8a58e86919b25d86a917a6f8808f Litecoin v0.8.6.9
aa77ae3a8c31b7bada91e53d451172f01405ce51 Litecoin v0.8.7.1
ccd9a1f5f72235244886d108f014d40d2d6c7bd5 Update testnet DNS seeds

# Not merged from Bitcoin


NOTMERGED
