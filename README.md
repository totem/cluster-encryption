# totem-encrypt [![Build Status](https://travis-ci.org/totem/totem-encrypt.svg)](https://travis-ci.org/totem/totem-encrypt) [![Coverage Status](https://coveralls.io/repos/totem/totem-encrypt/badge.svg)](https://coveralls.io/r/totem/totem-encrypt)
Python library for encryption/decryption in totem

It uses asymmetric cryptography using PKCS#1 v1.5.

### Dependencies

To install dependencies for the project, run command:  

```
pip install -r requirements.txt
```

In addition if you are developing on the project, run command: 

```
pip install -r dev-requirements.txt
```


## Testing

Tests are located in tests folder. Project uses nose for testing.

### Unit Tests

To run all unit tests , run command :

```
nosetests -w tests/unit
```

