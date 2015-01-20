import copy
from encryption.store.base import AbstractProvider


class InMemoryProvider(AbstractProvider):

    def __init__(self, init_values={}):
        self._store = copy.deepcopy(init_values)

    @staticmethod
    def _get_path(profile, public=True):
        suffix = '-pub' if public else '-priv'
        return '%s%s' % (profile, suffix)

    def write(self, profile, data, public=True):
        self._store[self._get_path(profile, public)] = data

    def load(self, profile, public=True):
        key_path = self._get_path(profile, public)
        if key_path in self._store:
            return self._store[key_path]
        else:
            # No encryption supported
            return None

    def delete(self, profile):
        for public in [True, False]:
            key_path = self._get_path(profile, public)
            if key_path in self._store:
                del(self._store[key_path])
