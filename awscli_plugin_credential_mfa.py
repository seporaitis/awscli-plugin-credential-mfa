import datetime
import getpass
import json
import logging
from copy import deepcopy
from hashlib import sha1

from botocore.credentials import (CachedCredentialFetcher,
                                  CanonicalNameCredentialSourcer,
                                  CredentialProvider, Credentials,
                                  DeferredRefreshableCredentials,
                                  JSONFileCache, create_mfa_serial_refresher)
from botocore.exceptions import (CredentialRetrievalError,
                                 InfiniteLoopConfigError, InvalidConfigError,
                                 PartialCredentialsError, ProfileNotFound)
from dateutil.tz import tzlocal

__version__ = '1.0.0'

logger = logging.getLogger(__name__)


def awscli_initialize(event_handlers):
    event_handlers.register(
        'session-initialized',
        inject_mfa_credential_provider,
        unique_id='inject_mfa_credential_provider',
    )


def inject_mfa_credential_provider(session, **kwargs):
    try:
        credential_provider = session.get_component('credential_provider')
    except ProfileNotFound:
        # If a user has provided a profile that does not exist,
        # trying to retrieve components/config on the session
        # will raise ProfileNotFound.  Sometimes this is invalid:
        #
        # "ec2 describe-instances --profile unknown"
        #
        # and sometimes this is perfectly valid:
        #
        # "configure set region us-west-2 --profile brand-new-profile"
        #
        # Because we can't know (and don't want to know) whether
        # the customer is trying to do something valid, we just
        # immediately return.  If it's invalid something else
        # up the stack will raise ProfileNotFound, otherwise
        # the configure (and other) commands will work as expected.
        logger.debug('ProfileNotFound caught when trying to inject mfa credential provider. '
                     'Credential provider not configured.')
        return

    credential_provider.insert_after(
        'env',
        MfaCredentialProvider(
            load_config=lambda: session.full_config,
            client_creator=session.create_client,
            cache=JSONFileCache(),
            profile_name=session.get_config_variable('profile') or 'default',
            credential_sourcer=CanonicalNameCredentialSourcer([
                credential_provider.get_provider('env'),
                credential_provider.get_provider('shared-credentials-file'),
                credential_provider.get_provider('config-file'),
            ]),
        ),
    )


def _local_now():
    return datetime.datetime.now(tzlocal())


class MfaCredentialFetcher(CachedCredentialFetcher):

    def __init__(self, client_creator, source_credentials, extra_args, mfa_prompter=None,
                 cache=None, expiry_window_seconds=60 * 15):
        """
        :type client_creator: callable
        :param client_creator: A callable that creates a client taking
            arguments like ``Session.create_client``.

        :type source_credentials: Credentials
        :param source_credentials: The credentials to use to create the
            client for the call to AssumeRole.

        :type extra_args: dict
        :param extra_args: Any additional arguments to add to the assume
            role request using the format of the botocore operation.
            Possible keys include, but may not be limited to,
            DurationSeconds, Policy, SerialNumber, ExternalId and
            RoleSessionName.

        :type mfa_prompter: callable
        :param mfa_prompter: A callable that returns input provided by the
            user (i.e raw_input, getpass.getpass, etc.).

        :type cache: dict
        :param cache: An object that supports ``__getitem__``,
            ``__setitem__``, and ``__contains__``.  An example of this is
            the ``JSONFileCache`` class in aws-cli.

        :type expiry_window_seconds: int
        :param expiry_window_seconds: The amount of time, in seconds,
        """
        self._client_creator = client_creator
        self._source_credentials = source_credentials

        if extra_args is None:
            self._extra_args = {}
        else:
            self._extra_args = deepcopy(extra_args)

        self._mfa_serial = self._extra_args.get('SerialNumber')

        self._mfa_prompter = mfa_prompter
        if self._mfa_prompter is None:
            self._mfa_prompter = getpass.getpass

        super(MfaCredentialFetcher, self).__init__(cache, expiry_window_seconds)

    def _create_cache_key(self):
        args = deepcopy(self._extra_args)
        frozen_credentials = self._source_credentials.get_frozen_credentials()

        args['AccessKeyId'] = frozen_credentials.access_key
        args['SecretAccessKey'] = frozen_credentials.secret_key

        args = json.dumps(args, sort_keys=True)
        argument_hash = sha1(args.encode('utf-8')).hexdigest()
        return self._make_file_safe(argument_hash)

    def _get_credentials(self):
        kwargs = self._get_session_token_kwargs()
        client = self._create_client()
        result = client.get_session_token(**kwargs)
        return result

    def _get_session_token_kwargs(self):
        kwargs = self._extra_args

        if self._mfa_serial is not None:
            prompt = 'Enter MFA code for {mfa_serial}: '.format(mfa_serial=self._mfa_serial)
            token_code = self._mfa_prompter(prompt)

            kwargs['TokenCode'] = token_code

        return kwargs

    def _create_client(self):
        frozen_credentials = self._source_credentials.get_frozen_credentials()
        return self._client_creator(
            'sts',
            aws_access_key_id=frozen_credentials.access_key,
            aws_secret_access_key=frozen_credentials.secret_key,
            aws_session_token=frozen_credentials.token,
        )


class MfaCredentialProvider(CredentialProvider):
    METHOD = 'mfa-credential-provider'
    CANONICAL_NAME = 'custom-MfaCredentials'

    ACCESS_KEY = 'aws_access_key_id'
    SECRET_KEY = 'aws_secret_access_key'
    MFA_SERIAL = 'mfa_serial'

    def __init__(self, load_config, client_creator, cache, profile_name, prompter=getpass.getpass,
                 credential_sourcer=None):
        """Initialize MfaCredentialProvider.

        :type load_config: callable
        :param load_config: A function that accepts no arguments, and
            when called, will return the full configuration dictionary
            for the session (``session.full_config``).

        :type client_creator: callable
        :param client_creator: A factory function that will create
            a client when called.  Has the same interface as
            ``botocore.session.Session.create_client``.

        :type cache: dict
        :param cache: An object that supports ``__getitem__``,
            ``__setitem__``, and ``__contains__``.  An example
            of this is the ``JSONFileCache`` class in the CLI.

        :type profile_name: str
        :param profile_name: The name of the profile.

        :type prompter: callable
        :param prompter: A callable that returns input provided
            by the user (i.e raw_input, getpass.getpass, etc.).

        :type credential_sourcer: CanonicalNameCredentialSourcer
        :param credential_sourcer: A credential provider that takes a
            configuration, which is used to provide the source credentials
            for the STS call.
        """
        self.cache = cache
        self._load_config = load_config
        self._client_creator = client_creator
        self._profile_name = profile_name
        self._prompter = prompter

        self._loaded_config = {}
        self._credential_sourcer = credential_sourcer
        self._visited_profiles = [self._profile_name]

    def load(self):
        self._loaded_config = self._load_config()
        profiles = self._loaded_config.get('profiles', {})
        profile = profiles.get(self._profile_name, {})

        if self._has_mfa_serial(profile):
            return self._load_mfa_creds(self._profile_name)

    def _has_mfa_serial(self, profile):
        return self.MFA_SERIAL in profile

    def _load_mfa_creds(self, profile_name):
        mfa_config = self._get_mfa_config(profile_name)
        source_credentials = self._resolve_source_credentials(mfa_config, profile_name)
        mfa_serial = mfa_config.get('mfa_serial')

        extra_args = {}
        if mfa_serial is not None:
            extra_args['SerialNumber'] = mfa_serial

        fetcher = MfaCredentialFetcher(
            client_creator=self._client_creator,
            source_credentials=source_credentials,
            extra_args=extra_args,
            mfa_prompter=self._prompter,
            cache=self.cache,
        )
        refresher = fetcher.fetch_credentials
        if mfa_serial is not None:
            refresher = create_mfa_serial_refresher(refresher)

        return DeferredRefreshableCredentials(
            method=self.METHOD,
            refresh_using=refresher,
            time_fetcher=_local_now,
        )

    def _get_mfa_config(self, profile_name):
        profiles = self._loaded_config.get('profiles', {})

        profile = profiles[profile_name]
        source_profile = profile.get('source_profile')
        credential_source = profile.get('credential_source')

        mfa_config = {
            'mfa_serial': profile.get('mfa_serial'),
            'source_profile': source_profile,
            'credential_source': credential_source,
        }

        if credential_source is not None and source_profile is not None:
            raise InvalidConfigError(
                error_msg=(
                    'The profile "{profile_name}" contains both source_profile and '
                    'credential_source.'.format(profile_name=profile_name)
                ),
            )
        elif credential_source is None and source_profile is None:
            raise PartialCredentialsError(
                provider=self.METHOD,
                cred_var='source_profile or credential_source',
            )
        elif credential_source is not None:
            self._validate_credential_source(profile_name, credential_source)
        else:
            self._validate_source_profile(profile_name, source_profile)

        return mfa_config

    def _validate_credential_source(self, profile_name, credential_source):
        if self._credential_sourcer is None:
            raise InvalidConfigError(
                error_msg=(
                    'The credential source "{credential_source}" is specified in profile '
                    '"{profile_name}", but no source_provider was configured.'.format(
                        credential_source=credential_source,
                        profile_name=profile_name,
                    ),
                ),
            )
        if not self._credential_sourcer.is_supported(credential_source):
            raise InvalidConfigError(
                error_msg=(
                    'The credential source "{credential_source}" referenced in profile '
                    '"{profile_name}" is not valid.'.format(
                        credential_source=credential_source,
                        profile_name=profile_name,
                    ),
                ),
            )

    def _source_profile_has_credentials(self, profile):
        return self._has_static_credentials(profile)

    def _validate_source_profile(self, parent_profile_name, source_profile_name):
        profiles = self._loaded_config.get('profiles', {})
        if source_profile_name not in profiles:
            raise InvalidConfigError(
                error_msg=(
                    'The source_profile "{source_profile}" referenced in the profile '
                    '"{parent_profile}" does not exist.'.format(
                        source_profile=source_profile_name,
                        parent_profile=parent_profile_name,
                    ),
                ),
            )

        source_profile = profiles[source_profile_name]

        if not self._source_profile_has_credentials(source_profile):
            raise InvalidConfigError(
                error_msg=(
                    'The source_profile "{source_profile}" must specify static '
                    'credentials.'.format(
                        source_profile=source_profile_name,
                    ),
                ),
            )

        if source_profile_name not in self._visited_profiles:
            return

        if source_profile_name != parent_profile_name:
            raise InfiniteLoopConfigError(
                source_profile=source_profile_name,
                visited_profiles=self._visited_profiles,
            )

        if not self._has_static_credentials(source_profile):
            raise InfiniteLoopConfigError(
                source_profile=source_profile_name,
                visited_profiles=self._visited_profiles,
            )

    def _has_static_credentials(self, profile):
        static_keys = [self.ACCESS_KEY, self.SECRET_KEY]
        return any(static_key in profile for static_key in static_keys)

    def _resolve_source_credentials(self, mfa_config, profile_name):
        credential_source = mfa_config.get('credential_source')
        if credential_source is not None:
            return self._resolve_credentials_from_source(credential_source, profile_name)

        source_profile = mfa_config['source_profile']
        self._visited_profiles.append(source_profile)
        return self._resolve_credentials_from_profile(source_profile)

    def _resolve_credentials_from_profile(self, profile_name):
        profiles = self._loaded_config.get('profiles', {})
        profile = profiles[profile_name]

        if self._has_static_credentials(profile):
            return self._resolve_static_credentials_from_profile(profile)

        return self._load_mfa_creds(profile_name)

    def _resolve_static_credentials_from_profile(self, profile):
        try:
            return Credentials(
                access_key=profile['aws_access_key_id'],
                secret_key=profile['aws_secret_access_key'],
                token=profile.get('aws_session_token'),
            )
        except KeyError as e:
            raise PartialCredentialsError(
                provider=self.METHOD,
                cred_var=str(e),
            )

    def _resolve_credentials_from_source(self, credential_source, profile_name):
        credentials = self._credential_sourcer.source_credentials(credential_source)
        if credentials is None:
            raise CredentialRetrievalError(
                provider=credential_source,
                error_msg=(
                    'No credentials found in credential_source referenced '
                    'in profile "{profile_name}".'.format(
                        profile_name=profile_name,
                    ),
                ),
            )
