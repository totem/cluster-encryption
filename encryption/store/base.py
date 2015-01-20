

class AbstractProvider:
    """
    Abstract provider defining methods for writing and loading profiles.

    root level:  Defaults for totem for all clusters.
    cluster level: Defaults for particular cluster.
    organization level: Defaults for particular organization
    repository: Defaults for particular repository
    ref level: Defaults for particular tag or a branch

    The implementation (like S3) must support multi level layout.
    """

    def not_supported(self):
        """
        Raises NotImplementedError with a message
        :return:
        """
        raise NotImplementedError(
            'Provider: %s does not support this operation' % self.__class__)

    def load(self, profile, public=True):
        """
        Load public key for given profile

        :param profile: String defining encryption profile (or key id)
        :type profile: str
        :keyword public: Boolean value specifying whether public or private key
            should be loaded.
        :type public: bool
        :return: Base64 encoded key
        :rtype: str
        :raise NotImplementedError: If provider does not support this method.
        """
        self.not_supported()

    def write(self, profile, data, public=True):
        """
        Write public key for given profile.

        :param profile: String defining encryption profile (or key id)
        :type profile: str
        :param data: Base64 encoded key
        :keyword public: Boolean value specifying whether public or private key
            should be loaded.
        :type public: bool
        :return: None
        :raise NotImplementedError: If provider does not support this method.
        """
        self.not_supported()

    def delete(self, profile):
        """
        Deletes public and private keys defined by the profile.

        :param profile: String defining encryption profile (or key id)
        :type profile: str
        :return: None
        :raise NotImplementedError: If provider does not support this method.
        """
        self.not_supported()
