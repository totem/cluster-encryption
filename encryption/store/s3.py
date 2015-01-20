from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.builtins import (  # noqa
    bytes, dict, int, list, object, range, str,
    ascii, chr, hex, input, next, oct, open,
    pow, round, super,
    filter, map, zip)
import boto
from boto.s3.key import Key
from encryption.store.base import AbstractProvider


class S3Provider(AbstractProvider):

    def __init__(self, bucket, keys_base='totem/keys'):
        self.bucket = bucket
        self.keys_base = keys_base

    @staticmethod
    def _s3_connection():
        # Use default env variable or IAM roles to connect to S3.
        return boto.connect_s3()

    def _s3_bucket(self):
        """
        Gets S3 bucket for storing totem configuration.

        :return: S3 Bucket
        :rtype: S3Bucket
        """
        return self._s3_connection().get_bucket(self.bucket)

    def _s3_path(self, profile, public=True):
        suffix = '-priv.pem' if not public else '-pub.pem'

        return '%s/%s%s' % (self.keys_base, profile, suffix)

    def _get_key(self, profile, public=True):
        path = self._s3_path(profile, public)
        return self._s3_bucket().get_key(path)

    def write(self, profile, data, public=True):
        key = Key(self._s3_bucket())
        key.key = self._s3_path(profile, public)
        key.set_contents_from_string(data)

    def load(self, profile, public=True):
        key = self._get_key(profile, public)
        if key:
            return key.get_contents_as_string()
        else:
            raise ValueError('Profile: %s and public:%s could not be found' %
                             (profile, public))

    def delete(self, profile):
        for public in [True, False]:
            key = self._get_key(profile, public)
            if key:
                key.delete()
