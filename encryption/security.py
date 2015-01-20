from future.builtins import (  # noqa
    bytes, dict, int, list, object, range,
    ascii, chr, hex, input, next, oct, open,
    pow, round, super,
    filter, map, zip)

import base64
import copy
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from encryption.store.inmemory import InMemoryProvider

DEFAULT_STORE = InMemoryProvider()
DEFAULT_PROFILE = 'default'
DEFAULT_CHUNK_SIZE = 256


def _encrypt_value(key, value, chunk_size=DEFAULT_CHUNK_SIZE):

    def _encrypt_chunk(key, value):
        return base64.urlsafe_b64encode(key.encrypt(value))

    if value is not None:
        value_enc = value + SHA.new(value).digest()
        value = None
        while len(value_enc) > 0:
            if value is not None:
                value += '\n'
            else:
                value = ''
            if len(value_enc) > chunk_size:
                chunk = value_enc[:chunk_size]
                value = value + _encrypt_chunk(key, chunk)
                value_enc = value_enc[chunk_size:]
            else:
                value = value + _encrypt_chunk(key, value_enc)
                value_enc = ''
        return value
    return None


def _decrypt_value(key, enc_value):
    dsize = SHA.digest_size
    sentinel = Random.new().read(15 + dsize)
    split_val = enc_value.splitlines()
    decrypted_val = ''
    for line in split_val:
        line_decrypted = key.decrypt(
            base64.urlsafe_b64decode(line.encode('utf-8')),
            sentinel)
        decrypted_val = decrypted_val + line_decrypted
    clear_val = decrypted_val[:-dsize]
    return clear_val


def _create_enc_key(profile, store):
    key_data = store.load(profile)
    return PKCS1_v1_5.new(RSA.importKey(key_data))


def _create_dec_key(profile, store, passphrase=None):
    key_data = store.load(profile, public=False)
    return PKCS1_v1_5.new(RSA.importKey(key_data, passphrase=passphrase))


def encrypt(value, profile=DEFAULT_PROFILE, store=DEFAULT_STORE,
            chunk_size=DEFAULT_CHUNK_SIZE, key=None):
    """
    Encrypts the given value using given profile and key store.

    :param value: String value that needs to be encrypted
    :keyword profile: Profile(Key Id) to be used for encryption
    :type profile: str
    :keyword store: Store to be used for encryption
    :type store: encryption.store.base.AbstractProvider
    :keyword key: PKCS1_v1_5 key
    :type key: Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher
    :return: Base64 Encrypted Encrypted value.
    :rtype: str or dict
    """
    key = key or _create_enc_key(profile, store)
    return _encrypt_value(key, value, chunk_size=chunk_size)


def decrypt(value, profile=DEFAULT_PROFILE, store=DEFAULT_STORE,
            passphrase=None, key=None):
    """
    Decrypts the given value using given profile and key store. Optionally
    the store can be protected by passphrase

    :param value: Base64 encrypted string or dictionary containg encrypted str.
    :type value: str or dict
    :keyword profile: Profile(Key Id) to be used for decryption
    :type profile: str
    :param store: Store to be used for decryption
    :type store: encryption.store.base.AbstractProvider
    :param passphrase: Passphrase for the private key. If None, key is
        un-protected
    :type passphrase: str
    :return: Decrypted String
    :rtype: str
    """
    key = key or _create_dec_key(profile, store, passphrase=passphrase)
    return _decrypt_value(key, value)


def encrypt_obj(value, profile=DEFAULT_PROFILE, store=DEFAULT_STORE,
                chunk_size=DEFAULT_CHUNK_SIZE, key=None):
    """
    Encrypts the given value using given profile and key store.

    :param value: value that needs to be encrypted
    :keyword profile: Profile(Key Id) to be used for encryption
    :type profile: str
    :keyword store: Store to be used for encryption
    :type store: encryption.store.base.AbstractProvider
    :keyword key: PKCS1_v1_5 key
    :type key: Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher
    :return: base64 encrypted values
    """
    def recurse(val):
        return encrypt_obj(val, profile=profile, store=store,
                           chunk_size=chunk_size, key=key)
    if hasattr(value, 'items'):
        if 'value' in value:

            if value.get('encrypted', False):
                return value
            else:
                copied_val = copy.deepcopy(value)
                copied_val['encrypted'] = True
                copied_val['value'] = \
                    encrypt(value['value'], profile=profile, store=store,
                            chunk_size=chunk_size, key=key)
                return copied_val
        else:
            return {
                k: recurse(v) for k, v in value.items()
            }
    elif isinstance(value, (list, set, tuple)):
        return [recurse(v) for v in value]
    else:
        return {
            'value': encrypt(str(value).encode('utf-8'),
                             profile=profile, store=store,
                             chunk_size=chunk_size, key=key),
            'encrypted': True
        }


def decrypt_obj(value, profile=DEFAULT_PROFILE, store=DEFAULT_STORE,
                passphrase=None, key=None):
    """
    Decrypts the given value using given profile and key store. Optionally
    the store can be protected by passphrase

    :param value: Base64 encrypted string or dictionary containg encrypted str.
    :type value: str or dict
    :keyword profile: Profile(Key Id) to be used for decryption
    :type profile: str
    :param store: Store to be used for decryption
    :type store: encryption.store.base.AbstractProvider
    :param passphrase: Passphrase for the private key. If None, key is
        un-protected
    :type passphrase: str
    :return: Decrypted object
    """
    def recurse(val):
        return decrypt_obj(val, profile=profile, store=store,
                           passphrase=passphrase, key=key)
    if hasattr(value, 'items'):
        if 'value' in value:
            if value.get('encrypted', False) and \
                    isinstance(value['value'], str):
                return decrypt(value['value'], profile=profile, store=store,
                               passphrase=passphrase, key=key)
            else:
                return value['value']
        else:
            return {
                k: recurse(v) for k, v in value.items()
            }
    elif isinstance(value, (list, set, tuple)):
        return [recurse(v) for v in value]
    else:
        return copy.deepcopy(value)
