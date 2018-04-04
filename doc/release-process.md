Release Process
====================

###Create a GPG key

 Off course only do this if you don't have a GPG key yet

	gpg --gen-key

 If you don't know what to choose you can use the following options

	(1) RSA and RSA (default)
	2048
	0 = key does not expire
	y
	Your name
	Your email
	Optionally a comment
	o
	Enter your passphrase twice

 If you generate GPG key through ssh and has no access to mouse, use the following command or equivalent to generate enough entropy:

	rngd -f -r /dev/urandom

###Create a Gitian build directory

 Before you start make sure the prerequisites for Gitian (vmbuilder, apt-cacher-ng, ruby) are installed

 https://github.com/devrandom/gitian-builder

 You only need to perform these steps when any of the build dependencies change.

 It's easy to create pull requests if you create your own fork of the gitian.sigs.git project, but you can also just share the signature in another form

	mkdir build
	cd build
	git clone https://github.com/cheebacoin-project/cheebacoin.git
	git clone https://github.com/devrandom/gitian-builder.git
	git clone https://github.com/cheebacoin-project/gitian.sigs.git

	mkdir gitian-builder/inputs
	cd gitian-builder/inputs

 Fetch the build dependencies

	wget 'http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.8.tar.gz' -O miniupnpc-1.8.tar.gz
	wget 'https://www.openssl.org/source/openssl-1.0.1h.tar.gz'
	wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
	wget 'http://zlib.net/zlib-1.2.8.tar.gz'
	wget 'ftp://ftp.simplesystems.org/pub/png/src/history/libpng16/libpng-1.6.8.tar.gz'
	wget 'https://fukuchi.org/works/qrencode/qrencode-3.4.3.tar.bz2'
	wget 'http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2'
	wget 'https://svn.boost.org/trac/boost/raw-attachment/ticket/7262/boost-mingw.patch' -O boost-mingw-gas-cross-compile-2013-03-03.patch
	wget 'https://download.qt-project.org/official_releases/qt/5.2/5.2.0/single/qt-everywhere-opensource-src-5.2.0.tar.gz'

 Create the VMs (and grab a coffee, or five). Make sure you have device mapper kernel module (dm-mod) loaded. If you are running a Linux distribution other than Ubuntu, you need to make sure /bin, /sbin, /usr/sbin are all in your PATH.

 The following may be run as a normal user or root:

	cd ../
	bin/make-base-vm --suite precise --arch i386
	bin/make-base-vm --suite precise --arch amd64

 Build the inputs (get some more coffee). Make sure you have KVM kernel module (kvm) loaded. If there is any error, you can check the log files (var/install.log, var/build.log).

 The following must be run as root:

	./bin/gbuild ../cheebacoin/contrib/gitian-descriptors/boost-linux.yml
	mv build/out/boost-*.zip inputs/
	./bin/gbuild ../cheebacoin/contrib/gitian-descriptors/deps-linux.yml
	mv build/out/bitcoin-deps-*.zip inputs/
	./bin/gbuild ../cheebacoin/contrib/gitian-descriptors/boost-win.yml
	mv build/out/boost-*.zip inputs/
	./bin/gbuild ../cheebacoin/contrib/gitian-descriptors/deps-win.yml
	mv build/out/bitcoin-deps-*.zip inputs/
	./bin/gbuild ../cheebacoin/contrib/gitian-descriptors/qt-win.yml
	mv build/out/qt-*.zip inputs/

* * *

###Double-check there are no upstream commits we could or should use

	bitcoin
	litecoin

###Update (commit) version in sources

 With all the VMs and dependency packages ready, it's time to make any necessary change to cheebacoin repository:

	cd ../cheebacoin

	cheebacoin-qt.pro
	doc/README*
	share/setup.nsi
	src/clientversion.h (change CLIENT_VERSION_IS_RELEASE to true)

###Write release notes. git shortlog helps a lot, for example:

	git shortlog --no-merges v0.7.2..v0.8.0

###Push the changes to Github

	git push

###Tag the release on Github

* * *

###Perform gitian builds

 From the build directory created above

	export SIGNER=(your PGP key used for gitian)
	export VERSION=1.4.0.0
	cd ../gitian-builder

 Build cheebacoind and cheebacoin-qt on Linux32, Linux64:

	./bin/gbuild --commit cheebacoin=v${VERSION} ../cheebacoin/contrib/gitian-descriptors/gitian-linux.yml
	./bin/gsign --signer "$SIGNER" --release ${VERSION} --destination ../gitian.sigs/ ../cheebacoin/contrib/gitian-descriptors/gitian-linux.yml
	pushd build/out
	zip -r cheebacoin-${VERSION}-linux-gitian.zip *
	mv cheebacoin-${VERSION}-linux-gitian.zip ../../
	popd

 Build cheebacoind and cheebacoin-qt on Win32:

	./bin/gbuild --commit cheebacoin=v${VERSION} ../cheebacoin/contrib/gitian-descriptors/gitian-win.yml
	./bin/gsign --signer "$SIGNER" --release ${VERSION}-win --destination ../gitian.sigs/ ../cheebacoin/contrib/gitian-descriptors/gitian-win.yml
	pushd build/out
	zip -r cheebacoin-${VERSION}-win-gitian.zip *
	mv cheebacoin-${VERSION}-win-gitian.zip ../../
	popd

 Build output expected:

  1. linux 32-bit and 64-bit binaries + source (cheebacoin-${VERSION}-linux-gitian.zip)
  2. windows 32-bit binaries, installer + source (cheebacoin-${VERSION}-win-gitian.zip)
  3. Gitian signatures (in gitian.sigs/${VERSION}[-win]/(your gitian key)/

 Commit your signature to gitian.sigs:

	cd ../gitian.sigs
	git add ${VERSION}/${SIGNER}
	git add ${VERSION}-win/${SIGNER}
	git commit -a
	git push  # Assuming you can push to the gitian.sigs tree, otherwise create a pull request

* * *

### After 3 or more people have gitian-built, repackage gitian-signed zips:

 From the gitian-builder directory created above

	export VERSION=1.4.0.0
	mkdir cheebacoin-${VERSION}-linux-gitian
	pushd cheebacoin-${VERSION}-linux-gitian
	unzip ../cheebacoin-${VERSION}-linux-gitian.zip
	mkdir gitian
	cp ../cheebacoin/contrib/gitian-downloader/*.pgp ./gitian/
	for signer in $(ls ../gitian.sigs/${VERSION}/); do
	 cp ../gitian.sigs/${VERSION}/${signer}/cheebacoin-build.assert ./gitian/${signer}-build.assert
	 cp ../gitian.sigs/${VERSION}/${signer}/cheebacoin-build.assert.sig ./gitian/${signer}-build.assert.sig
	done
	zip -r cheebacoin-${VERSION}-linux-gitian.zip *
	cp cheebacoin-${VERSION}-linux-gitian.zip ../
	popd
	mkdir cheebacoin-${VERSION}-win-gitian
	pushd cheebacoin-${VERSION}-win-gitian
	unzip ../cheebacoin-${VERSION}-win-gitian.zip
	mkdir gitian
	cp ../cheebacoin/contrib/gitian-downloader/*.pgp ./gitian/
	for signer in $(ls ../gitian.sigs/${VERSION}-win32/); do
	 cp ../gitian.sigs/${VERSION}-win/${signer}/cheebacoin-build.assert ./gitian/${signer}-build.assert
	 cp ../gitian.sigs/${VERSION}-win/${signer}/cheebacoin-build.assert.sig ./gitian/${signer}-build.assert.sig
	done
	zip -r cheebacoin-${VERSION}-win-gitian.zip *
	cp cheebacoin-${VERSION}-win-gitian.zip ../
	popd

repackage gitian builds for release as stand-alone zip/tar/installer exe

**Linux .tar.gz:**

	unzip cheebacoin-${VERSION}-linux-gitian.zip -d cheebacoin-${VERSION}-linux
	tar czvf cheebacoin-${VERSION}-linux.tar.gz cheebacoin-${VERSION}-linux
	rm -rf cheebacoin-${VERSION}-linux

**Windows .zip and setup.exe:**

	unzip cheebacoin-${VERSION}-win-gitian.zip -d cheebacoin-${VERSION}-win
	cp cheebacoin-${VERSION}-win/32/cheebacoin-*-setup.exe .
	zip -r cheebacoin-${VERSION}-win.zip cheebacoin-${VERSION}-win
	rm -rf cheebacoin-${VERSION}-win

###Next steps:

* Code-sign Windows -setup.exe (in a Windows virtual machine) and
  OSX Bitcoin-Qt.app (Note: only Gavin has the code-signing keys currently)

* upload builds to SourceForge

* create SHA256SUMS for builds, and PGP-sign it

* update cheebacoin.com version
  make sure all OS download links go to the right versions

* update forum version

* update reddit download links

-------------------------------------------------------------------------

- Celebrate

**Perform Mac build:**

 OSX binaries are compiled on Maverick using QT 4.8. Due to the complication with libstdc++ vs libc++, one should install the latest QT library using Homebrew:

	brew update
	brew install qt --HEAD
	/usr/local/bin/qmake -spec unsupported/macx-clang-libc++ cheebacoin-qt.pro USE_UPNP=1 STATIC=1
	make
	codesign -s "Developer ID" Cheebacoin-Qt.app
	export QTDIR=/usr/local/Cellar/qt/4.8.6/  # needed to find translations/qt_*.qm files
	T=$(contrib/qt_translations.py $QTDIR/translations src/qt/locale)
	python2.7 share/qt/clean_mac_info_plist.py
	python2.7 contrib/macdeploy/macdeployqtplus Cheebacoin-Qt.app -add-qt-tr $T -dmg -fancy contrib/macdeploy/fancy.plist

 Build output expected: Cheebacoin-Qt.dmg
