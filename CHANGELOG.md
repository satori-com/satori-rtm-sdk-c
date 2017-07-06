v2.0.0 (2017-07-17)
-------------------

* Major API change, see Migrating_to_API_v2.md for details
* Added a tutorial project and more examples
* cmake version requirement lowered from 3.4 to 2.8.11
  (found in some LTS distros)
* Added support for OpenSSL 1.1.0
* Fixed WebSocket frame encoding when payload length is 126 bytes
* Building without a TLS library is no longer supported
* Added parsers for different PDU types
* Added WebSocket ping / pong heartbeats
* Fixed bug in Apple TLS write method

v1.0.1 (2017-04-03)
-------------------

* [Core] Fixed issue with payload_length parsing for case with
  extended payload length
* [iOS wrapper] Added Cocoapods spec
* Added support for RTM role authentication when using GNUTLS or Apple SSL
  library (in v1.0.0 there was support only for OpenSSL)

v1.0.0 (2017-03-07)
-------------------

* Initial release.