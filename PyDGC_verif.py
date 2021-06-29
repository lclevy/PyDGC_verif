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

from Crypto.Util.asn1 import DerSequence, DerInteger, DerBitString, DerObjectId

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
  unhexlify(b'70aaa4460b56d17c') : b64decode(b'MIIDxjCCAa6gAwIBAgIIBHF1Rxam9iUwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIwNzIyMDBaFw0yMTA5MDIwNzIyMDBaMEwxCzAJBgNVBAYTAkZSMQ0wCwYDVQQKDARDTkFNMRIwEAYDVQQLDAkxODAwMzUwMjQxGjAYBgNVBAMMEVZBQ0NJX0FUVF9URVNUXzAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmnpWq9jI5KhCukndjsufKTNdbkduRQxCrVKz+uizlJCZsPH034+OycGTehFyw5zhCj9/wLgkr3aBwrxbsIjRxaNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUdx9kMh/WhPj8BLAgDJexNYvzKoswHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBhxW5O9/H3pp4xrITJEGYfpNoDeUWON4aKQo+8V434jeHebNz/5ImorYmbL92opXrF8CYhQa8tGXct92moungxO0QvIAZThOrbelCiPXIFKD5bKmpanPR8E9JVm6mAAXpU4r2AWxPuY74+xypgO2HwL5mgll3wBzaLFRocXzb79Aa7cfTcn5d8QJAabGmfxcln5Qh1vBVHYEt53nysN5azVB5xzZMFR9qVJrJ8xB0Ef5Qe4aOr3UCLrmULg0UYp+GoXLs1srMdJIwPCr1v/5eGyTEmuB32bNcIMU+S7Jf7j4fAZvTyigUd4PfTAZXGcdM8VFNrE5BKLP728UatLgPqFoELefenyLVNlJoMjlozNpWZjGq0cm2CYHF2/jutnx0RB2RkaH1MMDFaLK1rUpVoHKR6UN4bZjt2zu+IZe/cVX37VOljO3ITqX6VEAH9NYCyNgfKo2HVNJMjErKNPY7d79irZxgx1J9JxJa5cZuyoWFFko5mMTiuJPqVcTQRp1ggYuaAHFD0VeMyQVpQW0pBYtmz9Dzr3FvKw0xY99wcNVeHFKIgNk6erzG+VsIhzVAJcBUg444kANCmMnhI40B41GASmhE2ynGAEUrDBZToPrNaTMhiNsBl8jK90UQQvOhWhWkB+zGAiQldVcmh0B16WY76WyZezy+2nmfbvpchmA=='),   
  #from https://0bin.net/paste/E-9oC3N3#N31W48ZZ8eTMVYKu8Nk-PnOcsXYFfEiRItk/5gWp9yd, by https://twitter.com/gilbsgilbs
  unhexlify(b'7c62eebe0ea7e709') : b64decode(b'MIIEGzCCAgOgAwIBAgIUNWO7+/2lmGQGT1cep5petfsOFocwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEdvdXYxFDASBgNVBAMMC0NTQ0EtRlJBTkNFMB4XDTIxMDYxNDIyMDAwMFoXDTIzMDYxNDIyMDAwMFowRTELMAkGA1UEBhMCRlIxDTALBgNVBAoMBENOQU0xEjAQBgNVBAsMCTE4MDAzNTAyNDETMBEGA1UEAwwKRFNDX0ZSXzAxOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCJiBWroM8AeX/1cn0Nyk300qLpMAD1UoB2Vq7a3No+BbgFKcPzm0ZwPaQYzfx3VHNc3JfUjv77AhJx5F4cY8+GjgeAwgd0wHQYDVR0OBBYEFF6mKwOiAheaIxTCkdVKd8zgd7urMB8GA1UdIwQYMBaAFL6KLtbJ+SBOOicDCJdN7P3ZfcXmMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMC0GA1UdHwQmMCQwIqAgoB6GHGh0dHA6Ly9hbnRzLmdvdXYuZnIvY3NjYV9jcmwwGAYDVR0gBBEwDzANBgsqgXoBgUgfAwkBATA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAKGGGh0dHBzOi8vYW50LmdvdXYuZnIvY3NjYTANBgkqhkiG9w0BAQsFAAOCAgEAu8BaLZXFj9/e2/a59mBrOhY2m5SpcAoayxF3zOkIOt7LNX0QqHuomOyGLHMnAhNALgS2vhDXD0hhs96ZcKaystlMePpYsVRyaYa53GwMrGHiLwFxH5qQNClCcktAP++wCcdQXzTyZOn9/GNdmquW1PNMLPCEfqlnzWawdpITr+CYMXa9R5BEMmdX19F41HcoPRn9/X2uHW/ONmBywTwJ3s0U8F5HF21buZtxVDvX4ey+qINBru4MiGwgRCsklS9kDbl3ODUox0lwhs2VgQzqjALF4xYgsdN2LJezrwAiL8GMRAenmX9eDdgzMGnjKFT6yW8BCrPsyUnM15RAou3BrwIp6oxXHnR8wbeKG7pzZZY1J4zk4yYyihwxguWbUZGksJsNAQoNdNHBZtc8a7Oj5onLyUIetd7ELXxdk8uy7WVFeye5V8qJRhWrFyhWWFscQeY8GktefXiGEh6fxGfRU5R5b0PznxfMiA3olad3s17dr+jzqCM/hcY2FmUTjYrSrAyrhHdmCYIJ3US71If74UeMs6NZnQRRiu3tbAX+TiDOHsEHEIOHldbyQqFfclyiC26fHTqcNfIAxXPmPDQ1jpEmhRjFDlOWHoSnzsGZi/wa1kmSb6+2uHgUP/C/O2oi+yAk8GpwpEi8Sgv+HH/p7z0ympQK8IUOG/4K3/urdto=')
}
'''
I:\dev\PyDGC_verif>openssl x509 -in 7c62eebe0ea7e709 -inform der -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            35:63:bb:fb:fd:a5:98:64:06:4f:57:1e:a7:9a:5e:b5:fb:0e:16:87
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, O = Gouv, CN = CSCA-FRANCE
        Validity
            Not Before: Jun 14 22:00:00 2021 GMT
            Not After : Jun 14 22:00:00 2023 GMT
        Subject: C = FR, O = CNAM, OU = 180035024, CN = DSC_FR_019
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:22:62:05:6a:e8:33:c0:1e:5f:fd:5c:9f:43:72:
                    93:7d:34:a8:ba:4c:00:3d:54:a0:1d:95:ab:b6:b7:
                    36:8f:81:6e:01:4a:70:fc:e6:d1:9c:0f:69:06:33:
                    7f:1d:d5:1c:d7:37:25:f5:23:bf:be:c0:84:9c:79:
                    17:87:18:f3:e1
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                5E:A6:2B:03:A2:02:17:9A:23:14:C2:91:D5:4A:77:CC:E0:77:BB:AB
            X509v3 Authority Key Identifier:
                keyid:BE:8A:2E:D6:C9:F9:20:4E:3A:27:03:08:97:4D:EC:FD:D9:7D:C5:E6

            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 CRL Distribution Points:

                Full Name:
                  URI:http://ants.gouv.fr/csca_crl

            X509v3 Certificate Policies:
                Policy: 1.2.250.1.200.31.3.9.1.1

            Authority Information Access:
                CA Issuers - URI:https://ant.gouv.fr/csca

'''
with open(sys.argv[1], 'rb') as dgcf:
  dgc = dgcf.read()

'''
listcert = json.load(open('pub_keys.txt'))
for kid, cert in listcert.items():
  print(hexlify(b64decode(kid)))
  if unhexlify(b'7c62eebe0ea7e709') == b64decode(kid):
    print('found')
    open(hexlify(b64decode(kid)),'wb').write(b64decode(cert))
'''
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
  
  kid = pheader[4] #key identifier, kid, label 4
  
  if kid in cert_dict: #sha256(b64decode(cert_der)).digest()[:8] == kid
    print('  using kid %s' % hexlify(kid))
    # "The key identifier is defined as the first truncated 8 Bytes of a SHA256 Hash. The "kid" claim can also be used in the JWK concept"
    # https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v3_en.pdf, section 2.4
    
    print('[+]verifying COSE signature') #see https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
    cose_msg = CoseMessage.decode(decompressed)
    #print(cose_msg)
    
    #import public key parameters x and y
    pubkey_der =  DerSequence().decode(DerSequence().decode(DerSequence().decode( cert_dict[kid] )[0])[6])[1]
    #https://stackoverflow.com/questions/29583211/get-x-and-y-components-from-ecc-public-key-in-pem-format-using-openssl
    x = pubkey_der[4:4+32]
    y = pubkey_der[4+32:4+64]

    cose_key = {
      'KTY': 'EC2',
      'CURVE': 'P_256',
      'ALG': 'ES256',
      'X': x,
      'Y': y
      }
    cose_msg.key = CoseKey.from_dict(cose_key)  
    print('is signature valid ?', cose_msg.verify_signature() )
  else:
    print('  missing public key for kid %s' % hexlify(kid))  

  

