from mock import patch
from nose.tools import eq_, raises
from encryption.store.s3 import S3Provider

__author__ = 'sukrit'

provider = S3Provider('test-bucket')


def test_s3_path_for_public_key():
    """
    Should get s3 path for public key
    """

    # When: I get S3 path for public key
    s3path = provider._s3_path('default')

    # Then: Expected path is returned
    eq_(s3path, 'totem/keys/default-pub.pem')


def test_s3_path_for_private_key():
    """
    Should get s3 path for private key
    """

    # When: I get S3 path for public key
    s3path = provider._s3_path('default', public=False)

    # Then: Expected path is returned
    eq_(s3path, 'totem/keys/default-priv.pem')


@patch('encryption.store.s3.boto')
def test_write(mboto):
    """
    Should write key to S3
    """
    provider.write('default', 'mock-key')


@patch('encryption.store.s3.boto')
@raises(ValueError)
def test_load_for_non_existing_key(mboto):
    """
    Should fail to load non existing key
    """

    # Given: Non existing key path
    mboto.connect_s3().get_bucket().get_key.return_value = None

    # When: I load key for given profile
    provider.load('default')

    # Then: Profile fails to get loaded


@patch('encryption.store.s3.boto')
def test_load_for_existing_key(mboto):
    """
    Should load existing key
    """

    # Given: Existing key path
    mboto.connect_s3().get_bucket().get_key().get_contents_as_string\
        .return_value = 'MockKey'

    # When: I load key for given profile
    data = provider.load('default')

    # Then: Profile gets loaded successfully
    eq_(data, 'MockKey')


@patch('encryption.store.s3.boto')
def test_delete_existing_keys(mboto):
    """
    Should delete existing public and private keys
    """

    # When: I delete existing keys
    provider.delete('default')

    # Then: Existing keys get removed
    eq_(mboto.connect_s3().get_bucket().get_key().delete.call_count, 2)


@patch('encryption.store.s3.boto')
def test_delete_non_existing_keys(mboto):
    """
    Should not raise error for non existing profile.
    """

    # Given: Non existing key path
    mboto.connect_s3().get_bucket().get_key.return_value = None

    # When: I delete existing keys
    provider.delete('default')

    # Then: No error is raised
