=======
History
=======

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
