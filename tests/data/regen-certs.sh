#!/bin/sh

# Re-generate the self-signed certificates used for unit tests.
# This should not be needed until the certificates expire again.

PASS=pass:Mozilla
DAYS=7200

openssl req -x509 -days $DAYS -sha256 -newkey rsa:4096 -keyout MozFakeCA.key -out MozFakeCA.pem -outform PEM -subj "/C=US/ST=CA/L=Mountain View/O=Mozilla/OU=Release Engineering/CN=releng/" -passin $PASS -passout $PASS
openssl genrsa -out MozAuthenticode.key -des3 -passout $PASS 4096
openssl req -new -key MozAuthenticode.key -out MozAuthenticode.csr -subj "/C=US/ST=CA/L=Mountain View/O=Mozilla/OU=Release Engineering/CN=releng/" -passin $PASS -passout $PASS
openssl x509 -req -sha256 -days $DAYS -in MozAuthenticode.csr -CA MozFakeCA.pem -CAcreateserial -CAkey MozFakeCA.key -out cert.pem -outform PEM -passin $PASS
openssl rsa -in MozAuthenticode.key -out privkey.pem -passin $PASS

cp cert.pem twocerts.pem
cat cert.pem >> twocerts.pem

rm MozFakeCA.key
rm MozFakeCA.pem
rm MozFakeCA.srl
rm MozAuthenticode.key
rm MozAuthenticode.csr
