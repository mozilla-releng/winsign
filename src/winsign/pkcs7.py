from binascii import hexlify

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type import univ
from pyasn1_modules.rfc2315 import Certificate, TBSCertificate


def x509_to_pkcs7(cert):
    tbsCert, _ = der_decode(cert.tbs_certificate_bytes, TBSCertificate())
    retval = Certificate()
    retval["tbsCertificate"] = tbsCert
    retval["signatureAlgorithm"][
        "algorithm"
    ] = cert.signature_algorithm_oid.dotted_string
    retval["signatureAlgorithm"]["parameters"] = univ.Null("")
    retval["signatureValue"] = univ.BitString.fromHexString(hexlify(cert.signature))
    return retval
