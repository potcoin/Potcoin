1.1.X.X changes
===============

- A proper fork of the Litecoin project on Github was made, incorporating all the changes that were in 1.1.3.0:
  - Potcoin specific branding
  - Potcoin specific block time, size, ...
  - Update of leveldb to version 1.15
  - Implemented KGW including the fix for problems at block 44877
  - Add spaces every 3 decimals in Qt client
  
- Following has been changed in comparison to the source of 1.1.3.0:
  - Restored information on automated testing
  - Fixed Github URL's in various places
  - Restored copyright for Litecoin Developers
  - Changed references to "Potcoin Wiki" to Potcoin website
  - Changed references to potcoin.org to potcoin.com
  - Fixed reference to .pro file in mac build
  - Source formatting
  - Any "unnecessary" changes to makefiles have been reverted. If Litecoin can build it like this, we should be able to do so too
  - Kept references to Litecoin Wiki for SSL setup instructions as we don't have any (yet)
  - Removed Litecoin addresses from Qt dialog box examples
  - Kept <defaultcodec> tags in translations
  - Reverted disabling of CLIENT_VERSION_BUILD in version.h
  - Used the commit from bitcoin repo to update leveldb to 1.15
  - Updated the addresses in Qt tests to a valid POT address
  - Renamed litecoin.icns to potcoin.icns according to config file
