Potcoin integration/staging tree
================================

http://www.potcoin.com

Copyright (c) 2009-2015 Bitcoin Developers
Copyright (c) 2011-2015 Litecoin Developers
Copyright (c) 2014 Reddcoin Developers
Copyright (c) 2015 Potcoin Developers

What is Potcoin?
----------------

Around August 1st 2015, at block 975,000 Potcoin transitioned to Proof-of-Stake-Velocity (PoSV)
algorithm which replaced Proof-of-Work (PoW).
 - 40 Second block target
 - just under 220 million mined in PoW phase
 - 5% annual interest in PoSV phase
 - difficulty retarget: every block using Kimoto's gravity well

Potcoin first started in January 2014 as a variant of Litecoin using Scrypt as
the Proof-of-Work (PoW) hash algorithm.
 - 40 Second block target
 - 420 coins per block
 - subsidy halves every 280,000 blocks
 - difficulty retarget: every block using Kimoto's gravity well + Digisheild

For more information, as well as an immediately useable, binary version of
the Potcoin wallet client, please visit http://www.potcoin.com.

License
-------

Potcoin is released under the terms of the MIT license. See `COPYING` for more
information or see http://opensource.org/licenses/MIT.

Development process
-------------------

Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

If it is a simple/trivial/non-controversial change, then one of the Potcoin
development team members simply pulls it.

If it is a *more complicated or potentially controversial* change, then the patch
submitter will be asked to start a discussion (if they haven't already) on the
appropriate channels.

The patch will be accepted if there is broad consensus that it is a good thing.
Developers should expect to rework and resubmit patches if the code doesn't
match the project's coding conventions (see `doc/coding.txt`) or are
controversial.

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/potcoin-project/potcoin/tags) are created
regularly to indicate new official, stable release versions of Potcoin.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to
submit new unit tests for old code.

Unit tests for the core code are in `src/test/`. To compile and run them:

    cd src; make -f makefile.unix test

Unit tests for the GUI code are in `src/qt/test/`. To compile and run them:

    qmake BITCOIN_QT_TEST=1 -o Makefile.test bitcoin-qt.pro
    make -f Makefile.test
    ./potcoin-qt_test
