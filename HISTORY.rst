History
=======

2.2.0 (2021-10-13)
------------------
* Added support for osslsigncode 2.1+ (required -CAfile cli)
* updated documentation for packaging and ownership

2.1.0 (2021-07-14)
------------------
* Added support for MSIX/APPX signing

2.0.0 (2019-10-17)
------------------
* Breaking API: Some functions are now async. In particular, the top-level
  `sign_file` function is now an async function.
* Restructured module layout
* Added docs

1.3.0 (2019-09-12)
------------------

* Fixed old style timestamp generation
* Added signature verification code
* Removed autograph support. Client code can implement their own autograph
  signing hooks for `winsign.sign.sign_file`

1.2.0 (2019-09-10)
------------------

* Updated logging so that is_signed doesn't produce error logs when files aren't signed

1.1.0 (2019-09-05)
------------------

* Added is_signed method to check if files are signed


1.0.0 (2019-08-30)
------------------

* First release
