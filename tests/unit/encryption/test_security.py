from encryption import security
from nose.tools import eq_
from encryption.store.inmemory import InMemoryProvider
from tests.helper import dict_compare

TEST_PASSPHRASE = 'changeit'


class TestSecurity:

    def setup(self):
        self.store = InMemoryProvider({
            'default-priv': '''-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDdcOq8Byr+0S48T/C4ySG/dghHr0fOR/daLpuwIIb01eiN37fU
ILdbM6CfHE5wjt/YfW0Pq3eIum/LrHHJv3nJlPVL9Zo0PQtNAVwMoKlsDaam2ud8
vu+052JaDUPdq/F/KhRyEHn3BQdLvKI5sVt6pN9q6dCsx7jPksVet91LjwIDAQAB
AoGBAJrBdDrt431r4R0jXP83CU/OBGFcvRkLsHElC4ceZFKtP7YO+GDWcG3bedBY
rvT41LVuio6d7Y7vhHvZyzgMieYrGhh9AANdTDHs+IsPtTat2TCLUTYbWb917PwW
mGBqzv3tz2qhvVAPwjfUZFNBQR7Qu6VLqwDYq8f5arCMVxrxAkEA936XqWlwC5E2
vSArFD85Q26Ru6fI3zzL+nNCu9i6Xey9qPfg80qNR74G4EoklgEoUpr1XiZr0rgT
h+1Odut5dwJBAOUNHJbzk8PWdjJKERcri2/6nopIFZiAfpsXbJHjvYJ2K/vE3HPf
GaBMS48aczwSMKP1oEqheEyrR7ywd+itxKkCQF2nqfyRybSW3v/yjFq9Eg5SaRN6
CqlveEDuHPK4sM2aKKsoIhfuvkfHwRJe/DlHdtrLiM53+5Vh0wI86tRVh0ECQQCU
cVfq+Hb2P4Ige2HyGzVl4A1pXugoCnaCur6RGgBSkZVVuLKKobbw7SE24BR4hO1j
BSfZ1iWpwoNeZRuA/0TpAkEAzn97loT2Mfkud+KwrSAJ61e6DrW63HFhpMH4knk5
MikjM0bswz2tnNFEn3CqWGXpAx0nR+DUb81iY5Gzb2XZRg==
-----END RSA PRIVATE KEY-----''',

            'default-pub': '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdcOq8Byr+0S48T/C4ySG/dghH
r0fOR/daLpuwIIb01eiN37fUILdbM6CfHE5wjt/YfW0Pq3eIum/LrHHJv3nJlPVL
9Zo0PQtNAVwMoKlsDaam2ud8vu+052JaDUPdq/F/KhRyEHn3BQdLvKI5sVt6pN9q
6dCsx7jPksVet91LjwIDAQAB
-----END PUBLIC KEY-----''',

            'default-enc-priv': '''-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,0E7CD05C5E58478A

WimBFQIHO5q9xDy6OghJiZ/RI1NdpPXqxriYHb38sfz79X4nhpBDGF8bzRXMnIQu
glcDT6KJ9+ZPwWRpU5Dz12ezifuiaggYUgYgc1hjN0go4Ta1SZkJSdyKnMu+MriL
aQ/ogX2FUErVleD8z9VeUcu9LiGvSY3G3yo9nTOYbItllRtfryyhj5eu+P9c0pJp
veUf3XUWvh8gonunDYJbtIXM7FLWQYw9K4b9g5aF42HCWZq/Lar0pj4CmADRvlCc
X9GT5EC7EE9OMSs78G7Jh05oQTAzhTME9QmazW1C7sTC08pktuLdhjSieIthETaf
F34W8A4T9LkPNXc4H3sST2h7+X9T+YpiaJjAvdKFB7qKgBoE+skYl4Lu0ni8Msbr
5PLHDdIxgxW19CKHTxHvgg1IDQjfj8s5NhhXvBlrlKO1fN+SXELV4zNgElNCzAIQ
KaClQGUrKIRr7CFJ2cX43cNPMavIShJzbygh/rx5g4S7cY91ZVynofsotL/uHxCA
5JpeuGSRYcoRs67Ovwni90tp0yqcQZ9qE5hHUUMAKwg+Wm9OWoJK1fQGht06mpeZ
4/1OEY+PGsgsgTzgJAuvCI6W6ZOP6CmlVWPBF7c0rmFJo7aYUit90575ThEQnrrK
7CTN7wY+dioqU5abRi+Ly2IzhrSvezz/iy98GLS3cisZqp4MT6HbqHWofq7n0lvV
dig9I1Xd/948VXHoqETeNn0vkBDjKc0m6cBKzcsa42kMg2d/3nvRKA7ZZ1UVK/Zt
g9qlL7+x2KBAVVWre4rMERonAh21vA0KEHDakMciiL5tmGxczgLQJQ==
-----END RSA PRIVATE KEY-----''',

            'default-enc-pub': '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdcOq8Byr+0S48T/C4ySG/dghH
r0fOR/daLpuwIIb01eiN37fUILdbM6CfHE5wjt/YfW0Pq3eIum/LrHHJv3nJlPVL
9Zo0PQtNAVwMoKlsDaam2ud8vu+052JaDUPdq/F/KhRyEHn3BQdLvKI5sVt6pN9q
6dCsx7jPksVet91LjwIDAQAB
-----END PUBLIC KEY-----'''
        })

    def test_encrypt_decrypt_with_no_passphrase(self):
        """
        Should encrypt and decrypt data for private key with no passphrase
        :return:
        """

        encrypted = security.encrypt('test', store=self.store)
        decrypted = security.decrypt(encrypted, store=self.store)

        eq_(decrypted, 'test')

    def test_encrypt_decrypt_with_passphrase(self):
        """
        Should encrypt and decrypt data for private key with no passphrase
        :return:
        """

        encrypted = security.encrypt('test', profile='default-enc',
                                     store=self.store)
        decrypted = security.decrypt(encrypted, profile='default-enc',
                                     store=self.store,
                                     passphrase=TEST_PASSPHRASE)

        eq_(decrypted, 'test')

    def test_encrypt_with_data_length_greater_than_chunk_size(self):
        encrypted = security.encrypt('test', store=self.store, chunk_size=2)
        decrypted = security.decrypt(encrypted, store=self.store)

        eq_(decrypted, 'test')

    def test_encrypt_decrypt_dictionary(self):

        # Given: Dictionary with values that needs to be encrypted
        data = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': ['value3.1', 'value3.2'],
            'key4': {
                'encrypted': False,
                'value': 'value4'
            }
        }

        # When: I encrypt and decrypt the dictionary
        encrypted = security.encrypt_obj(data, store=self.store)
        decrypted = security.decrypt_obj(encrypted, store=self.store)

        # Then: Original dictionary is returned
        print(encrypted)
        dict_compare(decrypted, {
            'key1': 'value1',
            'key2': 'value2',
            'key3': ['value3.1', 'value3.2'],
            'key4': 'value4'
        })
