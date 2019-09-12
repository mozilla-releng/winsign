=======
winsign
=======

.. image:: https://img.shields.io/pypi/v/winsign.svg
        :target: https://pypi.python.org/pypi/winsign

Utilities to support code signing Windows executable files.

* Works on Python 3.6 and up.
* Free software: MPL2
* Requires osslsigncode to operate from e.g. https://github.com/theuni/osslsigncode


Installation
------------
`pip install winsign`

CLI Usage
---------
::

   usage: winsign [-h] --certs CERTS --key PRIV_KEY [-n COMMENT] [-i URL] -d
                  {sha1,sha256} [-t {old,rfc3161}] [-v] [-q]
                  infile [outfile]

   positional arguments:
     infile            unsigned file to sign
     outfile           where to write output to. defaults to infile

   optional arguments:
     -h, --help        show this help message and exit
     --certs CERTS     certificates to include in the signature
     --key PRIV_KEY    private key used to sign
     -n COMMENT        comment to include in signature
     -i URL            url to include in signature
     -d {sha1,sha256}  digest to use for signing. must be one of sha1 or sha256
     -t {old,rfc3161}
     -v, --verbose
     -q, --quiet

Credits
-------

* Chris AtLee <catlee@mozilla.com>
