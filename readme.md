# PyDGC_verif.py

python experiment to decode European Union Digital Green Certificate



@lorenzo2472



verification not found yet

#### Decoding example


```
I:\dev\PyDGC_verif>python PyDGC.py dgc2.txt
[+]base45 decoding
[+]zlib decompress
[+]CBOR decoding
[b'\xa2\x01&\x04Hp\xaa\xa4F\x0bV\xd1|', {}, b'\xa4\x01bFR\x04\x1aa\x10S\xe0\x06\x1a`\xbf\xe8`9\x01\x03\xa1\x01\xa4av\x81\xaabcix\x1durn:uvci:01:FR:KKF3BYIGYSVF#QbcobFRbdn\x01bdtj2021-03-01bisdCNAMbmamORG-100030215bmplEU/1/20/1528bsd\x02btgi840539006bvpj1119349007cdobj1962-05-31cnam\xa4bfnotheoule sur merbgnkjean pierrecfntoTHEOULE<SUR<MERcgntkJEAN<PIERREcvere1.0.0', b'\xebKSB\xa3x\x17\xb5\xd0\xc6\xda\x80\xaa\xf1}6N\xa0\x80\xad\xa26\x96Xfn,\xb8\xc6K\xebe7\xfe\x9e\xa0\x82\xda\xa7\x08\x1f\x16\xac\xfc\xe33\x9c\xca\xf3\x1c\xf0g\x11\xfb\n\xc4\xd1\x81\x1eH\x1a\xab\xdc?']
[+]decoding COSE protected header
{1: -7, 4: b'p\xaa\xa4F\x0bV\xd1|'}
kid: b'70aaa4460b56d17c'
[+]decoding payload
{
  "1": "FR",
  "4": 1628460000,
  "6": 1623189600,
  "-260": {
    "1": {
      "v": [
        {
          "ci": "urn:uvci:01:FR:KKF3BYIGYSVF#Q",
          "co": "FR",
          "dn": 1,
          "dt": "2021-03-01",
          "is": "CNAM",
          "ma": "ORG-100030215",
          "mp": "EU/1/20/1528",
          "sd": 2,
          "tg": "840539006",
          "vp": "1119349007"
        }
      ],
      "dob": "1962-05-31",
      "nam": {
        "fn": "theoule sur mer",
        "gn": "jean pierre",
        "fnt": "THEOULE<SUR<MER",
        "gnt": "JEAN<PIERRE"
      },
      "ver": "1.0.0"
    }
  }
}
[+]COSE ECDSA signature:
b'eb4b5342a37817b5d0c6da80aaf17d364ea080ada2369658666e2cb8c64beb6537fe9ea082daa7081f16acfce3339ccaf31cf06711fb0ac4d1811e481aabdc3f' 64
[+]verifying COSE signature
```

### References

- https://ec.europa.eu/health/ehealth/covid-19_en
- https://datatracker.ietf.org/doc/html/rfc8152
- https://github.com/eu-digital-green-certificates