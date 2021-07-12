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

#exemple dgc1.txt (FR) is from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/FR/2DCode/raw/DGC_QrCode_00001_Raw.json

cert_dict = {
  #from DGC_QrCode_00001_Raw.json, Subject: C = FR, O = CNAM, OU = 180035024, CN = VACCI_ATT_TEST_01
  unhexlify(b'70aaa4460b56d17c') : b64decode(b'MIIDxjCCAa6gAwIBAgIIBHF1Rxam9iUwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA2MDIwNzIyMDBaFw0yMTA5MDIwNzIyMDBaMEwxCzAJBgNVBAYTAkZSMQ0wCwYDVQQKDARDTkFNMRIwEAYDVQQLDAkxODAwMzUwMjQxGjAYBgNVBAMMEVZBQ0NJX0FUVF9URVNUXzAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmnpWq9jI5KhCukndjsufKTNdbkduRQxCrVKz+uizlJCZsPH034+OycGTehFyw5zhCj9/wLgkr3aBwrxbsIjRxaNdMFswCQYDVR0TBAIwADAdBgNVHQ4EFgQUdx9kMh/WhPj8BLAgDJexNYvzKoswHwYDVR0jBBgwFoAUYLoYTllzE2jOy3VMAuU4OJjOingwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBhxW5O9/H3pp4xrITJEGYfpNoDeUWON4aKQo+8V434jeHebNz/5ImorYmbL92opXrF8CYhQa8tGXct92moungxO0QvIAZThOrbelCiPXIFKD5bKmpanPR8E9JVm6mAAXpU4r2AWxPuY74+xypgO2HwL5mgll3wBzaLFRocXzb79Aa7cfTcn5d8QJAabGmfxcln5Qh1vBVHYEt53nysN5azVB5xzZMFR9qVJrJ8xB0Ef5Qe4aOr3UCLrmULg0UYp+GoXLs1srMdJIwPCr1v/5eGyTEmuB32bNcIMU+S7Jf7j4fAZvTyigUd4PfTAZXGcdM8VFNrE5BKLP728UatLgPqFoELefenyLVNlJoMjlozNpWZjGq0cm2CYHF2/jutnx0RB2RkaH1MMDFaLK1rUpVoHKR6UN4bZjt2zu+IZe/cVX37VOljO3ITqX6VEAH9NYCyNgfKo2HVNJMjErKNPY7d79irZxgx1J9JxJa5cZuyoWFFko5mMTiuJPqVcTQRp1ggYuaAHFD0VeMyQVpQW0pBYtmz9Dzr3FvKw0xY99wcNVeHFKIgNk6erzG+VsIhzVAJcBUg444kANCmMnhI40B41GASmhE2ynGAEUrDBZToPrNaTMhiNsBl8jK90UQQvOhWhWkB+zGAiQldVcmh0B16WY76WyZezy+2nmfbvpchmA=='),   

  #from https://0bin.net/paste/E-9oC3N3#N31W48ZZ8eTMVYKu8Nk-PnOcsXYFfEiRItk/5gWp9yd, by https://twitter.com/gilbsgilbs
  
  #certificate, Subject: C = FR, O = CNAM, OU = 180035024, CN = DSC_FR_019
  unhexlify(b'7c62eebe0ea7e709') : b64decode(b'MIIEGzCCAgOgAwIBAgIUNWO7+/2lmGQGT1cep5petfsOFocwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEdvdXYxFDASBgNVBAMMC0NTQ0EtRlJBTkNFMB4XDTIxMDYxNDIyMDAwMFoXDTIzMDYxNDIyMDAwMFowRTELMAkGA1UEBhMCRlIxDTALBgNVBAoMBENOQU0xEjAQBgNVBAsMCTE4MDAzNTAyNDETMBEGA1UEAwwKRFNDX0ZSXzAxOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCJiBWroM8AeX/1cn0Nyk300qLpMAD1UoB2Vq7a3No+BbgFKcPzm0ZwPaQYzfx3VHNc3JfUjv77AhJx5F4cY8+GjgeAwgd0wHQYDVR0OBBYEFF6mKwOiAheaIxTCkdVKd8zgd7urMB8GA1UdIwQYMBaAFL6KLtbJ+SBOOicDCJdN7P3ZfcXmMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMC0GA1UdHwQmMCQwIqAgoB6GHGh0dHA6Ly9hbnRzLmdvdXYuZnIvY3NjYV9jcmwwGAYDVR0gBBEwDzANBgsqgXoBgUgfAwkBATA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAKGGGh0dHBzOi8vYW50LmdvdXYuZnIvY3NjYTANBgkqhkiG9w0BAQsFAAOCAgEAu8BaLZXFj9/e2/a59mBrOhY2m5SpcAoayxF3zOkIOt7LNX0QqHuomOyGLHMnAhNALgS2vhDXD0hhs96ZcKaystlMePpYsVRyaYa53GwMrGHiLwFxH5qQNClCcktAP++wCcdQXzTyZOn9/GNdmquW1PNMLPCEfqlnzWawdpITr+CYMXa9R5BEMmdX19F41HcoPRn9/X2uHW/ONmBywTwJ3s0U8F5HF21buZtxVDvX4ey+qINBru4MiGwgRCsklS9kDbl3ODUox0lwhs2VgQzqjALF4xYgsdN2LJezrwAiL8GMRAenmX9eDdgzMGnjKFT6yW8BCrPsyUnM15RAou3BrwIp6oxXHnR8wbeKG7pzZZY1J4zk4yYyihwxguWbUZGksJsNAQoNdNHBZtc8a7Oj5onLyUIetd7ELXxdk8uy7WVFeye5V8qJRhWrFyhWWFscQeY8GktefXiGEh6fxGfRU5R5b0PznxfMiA3olad3s17dr+jzqCM/hcY2FmUTjYrSrAyrhHdmCYIJ3US71If74UeMs6NZnQRRiu3tbAX+TiDOHsEHEIOHldbyQqFfclyiC26fHTqcNfIAxXPmPDQ1jpEmhRjFDlOWHoSnzsGZi/wa1kmSb6+2uHgUP/C/O2oi+yAk8GpwpEi8Sgv+HH/p7z0ympQK8IUOG/4K3/urdto='),
  #pcr, Subject: C = FR, O = APHP, OU = 26750045200011, CN = DSC_FR_001
  unhexlify(b'7be6c5772c322501') : b64decode(b'MIIEIDCCAgigAwIBAgIUbNtFh5SyNNW36Tj3lSGsVZ1yzJkwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEdvdXYxFDASBgNVBAMMC0NTQ0EtRlJBTkNFMB4XDTIxMDYxMDIyMDAwMFoXDTIzMDYxMDIyMDAwMFowSjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEFQSFAxFzAVBgNVBAsMDjI2NzUwMDQ1MjAwMDExMRMwEQYDVQQDDApEU0NfRlJfMDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERuPqA8PXwAZlb3MnIn+3UajY2JjRkt4v3rI4nUuQjh23nZZ/3rDqaJ8Jbow+pKFgdWA51sZ6pQIyIX76wYfrCqOB4DCB3TAdBgNVHQ4EFgQUkqfVrNfmsMs1UB/NA0C3KVEx3O4wHwYDVR0jBBgwFoAUvoou1sn5IE46JwMIl03s/dl9xeYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0fBCYwJDAioCCgHoYcaHR0cDovL2FudHMuZ291di5mci9jc2NhX2NybDAYBgNVHSAEETAPMA0GCyqBegGBSB8DCQEBMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAoYYaHR0cHM6Ly9hbnQuZ291di5mci9jc2NhMA0GCSqGSIb3DQEBCwUAA4ICAQAhOMLYhWn1iV43jduVRRivgVT1jYwHmouj7nff+S7gVnxiIlX52jc/VmQDl6xOZjBHUBiRTRqjan1tdH1LvBfg1HoZWv3HaC5HbfkMu0nqItE5zbFwtJGsUpHRTSP/wrjqL83o5akkR8Uw/iIYhkLvuEKH3/ZqwZYRwOJ/NyXJnKgRuHvgsL0zbwf5X2EdbqaTtDDGHHCbg68o8CqkQ/guBP0jKHXBFWgboMQB2bruquGqVO2xKIZIU2E3sc3dhNbDYGD3KfgJbdFtnbISvxaIfnCn3anZtQgonSsHc0LWIpgobY+NxXSNfBKzICdI350hhmnHz2NS2VtrF0Xa59kZd/WMPcOzlfKi6aVI/Y+LcpujeO9ujlFGNU6aMxi2s9RWy31tjWxsOmr/sbEKF25YGuTWwvqe/MgXzpbTF0C1lVcARXaBVT8Q18nNbLLK/VLAtzjLYTblFM4zdXA5ZnfCqXDqZZathkyyf8aY/svDELxROVm72F9GnYC/OqnGeCOed+Iscp8ne8HUTgT0iNFiAR1pRz25v047QFE7G7jwo4YTA+ynwCxnVaoK3pkyfIiXstyPxMpu3Q7t90br/mAPDCWDHFpvxqvPcRlMpd3p5JcjiurGreGbivgPdJYGRPbWb/Kwp/99ACqZFA8FaGL7aP+ivAO6cBv6DNF2XXvoww=='),
  #antigenique, Subject: C = FR, O = APHP, OU = 26750045200011, CN = DSC_FR_002
  unhexlify(b'790398e810e9faf3') : b64decode(b'MIIEIDCCAgigAwIBAgIUQporYv8Mt3ziR1r6G4s54HzRVpcwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEdvdXYxFDASBgNVBAMMC0NTQ0EtRlJBTkNFMB4XDTIxMDYxMDIyMDAwMFoXDTIzMDYxMDIyMDAwMFowSjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEFQSFAxFzAVBgNVBAsMDjI2NzUwMDQ1MjAwMDExMRMwEQYDVQQDDApEU0NfRlJfMDAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx2sQ7slwQ+IQrSLZwgIfafTa2g144vB8OXnI5WU67BHfTazsPcfNbWUj5uq/fFB5EEblaSEpRA5YwhyfAEIt4qOB4DCB3TAdBgNVHQ4EFgQUxhlqVg/2EyJWoDdVGkyJrsY4CXkwHwYDVR0jBBgwFoAUvoou1sn5IE46JwMIl03s/dl9xeYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0fBCYwJDAioCCgHoYcaHR0cDovL2FudHMuZ291di5mci9jc2NhX2NybDAYBgNVHSAEETAPMA0GCyqBegGBSB8DCQEBMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAoYYaHR0cHM6Ly9hbnQuZ291di5mci9jc2NhMA0GCSqGSIb3DQEBCwUAA4ICAQCbA+2eQnPJWMmh2eIH1gMJhggl5GSmOBFKeXyC4jeYQSDRY97/rsDWRXAYtE4DgZQO1cZcwsM4ybbZ+khmb0iCeO/0oiKIux8FU14B7zFksZFxZpbUSAJGD9lE1xRFnfUIyoPL3lza7lWqZ8lSfLuoqoN4mODkGpPYwWu/GC8sR3ynDt2jhrdBcLnos3k47+4ZRypwDnv9FRU4/9fEnl3Y4iK+hUtq83tI5offQETsXIq+VMmcw6zmeUTaMcHRnnMo4WknrSHbe9x1MOwQmADn7ZjYzMooI4TyM/dzo1IOH8iovgMbJP7zxWqp8zgtqZPpDtp500V9yCBjGCQWgRofrBhUojKj4BkGslCZaHHkRqp0A7WOIejCpCYwNRhom3Hu8oClJ0fGcIEIrdybYISYemClnbSlM+tXt9vATf7oMRZgXSGR/9HrY95naG5U7/+eHRgm3qHAJbbbTDHET7ba+Wiq9rnYScChSH/bMN2yLsuBcpVozokcX6k2l69KVzAsVtKCjPS/ISBWHDiEaVx++RyPB5YfbVX7ykJ4SaWX1ED6DLeszCdcLNb57i1Xu35kb1SGh+CUeALUEqBtJUcEheLixnTxJIHG2xq59a560SsZBdMf8r/qYTz9DqEgBXPSlNeHn5aIG/2u0bLrM3Q9GvBk4zBj3C4zWZJVUTZBNA==')

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

  

