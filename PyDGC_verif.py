'''
how to decode and verify EU digital green certificates

https://ec.europa.eu/health/ehealth/covid-19_en

delivered in France by https://attestation-vaccin.ameli.fr/attestation

Laurent Clevy @lorenzo2472

depends on https://pypi.org/project/cose/ and https://pypi.org/project/cbor2/

'''

from binascii import hexlify, unhexlify
from base45 import b45decode
from base64 import b64decode
from zlib import decompress
from hashlib import sha256

import json
import cbor2
from cose.messages import CoseMessage
from cose.keys import CoseKey

import sys

'''
for dgc1.txt example (DGC_QrCode_00001_Raw.json)
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:71:75:47:16:a6:f6:25
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = IMPRIMERIE NATIONALE, OU = FOR TEST PURPOSE ONLY, CN = INGROUPE DSc CA
        Validity
            Not Before: Jun  2 07:22:00 2021 GMT
            Not After : Sep  2 07:22:00 2021 GMT
        Subject: C = FR, O = CNAM, OU = 180035024, CN = VACCI_ATT_TEST_01
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9a:7a:56:ab:d8:c8:e4:a8:42:ba:49:dd:8e:cb:
                    9f:29:33:5d:6e:47:6e:45:0c:42:ad:52:b3:fa:e8:
                    b3:94:90:99:b0:f1:f4:df:8f:8e:c9:c1:93:7a:11:
                    72:c3:9c:e1:0a:3f:7f:c0:b8:24:af:76:81:c2:bc:
                    5b:b0:88:d1:c5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Key Identifier:
                77:1F:64:32:1F:D6:84:F8:FC:04:B0:20:0C:97:B1:35:8B:F3:2A:8B
            X509v3 Authority Key Identifier:
                keyid:60:BA:18:4E:59:73:13:68:CE:CB:75:4C:02:E5:38:38:98:CE:8A:78

            X509v3 Key Usage: critical
'''
#exemple dgc1.txt (FR) is from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/FR/2DCode/raw/DGC_QrCode_00001_Raw.json

cert_dict = {
  #from DGC_QrCode_00001_Raw.json
  unhexlify(b'70aaa4460b56d17c') : b64decode(b'MIIDxjCCAa6gAwIBAgIIBHF1Rxam9iUwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIwNzIyMDBaFw0yMTA5MDIwNzIyMDBaMEwxCzAJBgNVBAYTAkZSMQ0wCwYDVQQKDARDTkFNMRIwEAYDVQQLDAkxODAwMzUwMjQxGjAYBgNVBAMMEVZBQ0NJX0FUVF9URVNUXzAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmnpWq9jI5KhCukndjsufKTNdbkduRQxCrVKz+uizlJCZsPH034+OycGTehFyw5zhCj9/wLgkr3aBwrxbsIjRxaNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUdx9kMh/WhPj8BLAgDJexNYvzKoswHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBhxW5O9/H3pp4xrITJEGYfpNoDeUWON4aKQo+8V434jeHebNz/5ImorYmbL92opXrF8CYhQa8tGXct92moungxO0QvIAZThOrbelCiPXIFKD5bKmpanPR8E9JVm6mAAXpU4r2AWxPuY74+xypgO2HwL5mgll3wBzaLFRocXzb79Aa7cfTcn5d8QJAabGmfxcln5Qh1vBVHYEt53nysN5azVB5xzZMFR9qVJrJ8xB0Ef5Qe4aOr3UCLrmULg0UYp+GoXLs1srMdJIwPCr1v/5eGyTEmuB32bNcIMU+S7Jf7j4fAZvTyigUd4PfTAZXGcdM8VFNrE5BKLP728UatLgPqFoELefenyLVNlJoMjlozNpWZjGq0cm2CYHF2/jutnx0RB2RkaH1MMDFaLK1rUpVoHKR6UN4bZjt2zu+IZe/cVX37VOljO3ITqX6VEAH9NYCyNgfKo2HVNJMjErKNPY7d79irZxgx1J9JxJa5cZuyoWFFko5mMTiuJPqVcTQRp1ggYuaAHFD0VeMyQVpQW0pBYtmz9Dzr3FvKw0xY99wcNVeHFKIgNk6erzG+VsIhzVAJcBUg444kANCmMnhI40B41GASmhE2ynGAEUrDBZToPrNaTMhiNsBl8jK90UQQvOhWhWkB+zGAiQldVcmh0B16WY76WyZezy+2nmfbvpchmA==')   
}

with open(sys.argv[1], 'rb') as dgcf:
  dgc = dgcf.read()

#health certificate, v1 : see https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v3_en.pdf, section 2.3
if dgc[:3] == b'HC1': 
  #https://pypi.org/project/base45, https://datatracker.ietf.org/doc/draft-faltstrom-base45/
  print('[+]base45 decoding')
  compressed = b45decode(dgc[4:]) #zlib compressed, see section 2.2 of digital-green-certificates_v3_en.pdf
  print('[+]zlib decompress')
  decompressed = decompress(compressed)
  #see 2.1 of digital-green-certificates_v3_en.pdf
  print('[+]CBOR decoding')
  obj = cbor2.loads(decompressed)

  assert obj.tag == 18 #18 = cose-sign1, see rfc8152
  #cbor encoding : major type = 6 (tag, 110), tag value = 18 (10010) = 0xd2 (110 10010) 
  
  print(obj.value)
  #https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf, section 3.3.1
  #cose structure [protected header, unprotected header, payload] see COSE, https://datatracker.ietf.org/doc/html/rfc8152
  #cbor encoding : major type = 4 (array, 100), argument = 4 (length of array 00100) = 0x84 (100 00100)
  
  #protected header
  print('[+]decoding COSE protected header')
  
  pheader = cbor2.loads(obj.value[0]) 

  assert pheader[1] == -7 #-7 is ECDSA : https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
  
  kid = pheader[4] #key identifier, kid, label 4
  
  if kid in cert_dict: #sha256(b64decode(cert_der)).digest()[:8] == kid
    print('  using kid %s' % hexlify(kid))
    # "The key identifier is defined as the first truncated 8 Bytes of a SHA256 Hash. The "kid" claim can also be used in the JWK concept"
    # https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v3_en.pdf, section 2.4
    
    #payload, see https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
    print('[+]decoding payload')
    print(json.dumps(cbor2.loads(obj.value[2]),indent=2)) #https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-value-sets_en.pdf
    #1 iss, issuer
    #4 iat, issued at
    #6 exp, expiration time
    #-260 hcert

    #signature
    print('[+]COSE ECDSA signature:')
    print(hexlify(obj.value[3]), len(obj.value[3]))  

    print('[+]verifying COSE signature') #see https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
    cose_msg = CoseMessage.decode(decompressed)
    #print(cose_msg)
    #import public key parameters x and y

    #https://stackoverflow.com/questions/29583211/get-x-and-y-components-from-ecc-public-key-in-pem-format-using-openssl
    ecc_pub = unhexlify(b'049a7a56abd8c8e4a842ba49dd8ecb9f29335d6e476e450c42ad52b3fae8b3949099b0f1f4df8f8ec9c1937a1172c39ce10a3f7fc0b824af7681c2bc5bb088d1c5')

    cose_key = {
      'KTY': 'EC2',
      'CURVE': 'P_256',
      'ALG': 'ES256',
      'X': ecc_pub[1:33],
      'Y': ecc_pub[33:]
      }
    cose_msg.key = CoseKey.from_dict(cose_key)  
    print('is signature valid ?', cose_msg.verify_signature() )
  else:
    print('  missing public key')  

  

