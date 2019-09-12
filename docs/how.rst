How it works
============

First we generate a dummy signature for the file using builtin keys. This uses
the :meth:`get_dummy_signature <winsign.sign.get_dummy_signature>` method.

We then take the extracted signature, and retrieve the ASN.1 SignedData object
from it. We replace the certificates in the SignerInfo object with the real
certificates. Then we can generate a signature over the new SignerInfo object
with whatever mechanism we wish.

Finally, the resulting signature is injected into the original file.
