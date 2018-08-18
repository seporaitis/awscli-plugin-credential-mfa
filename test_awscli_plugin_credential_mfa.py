from datetime import datetime, timedelta

import mock
import pytest
from botocore.credentials import Credentials
from botocore.exceptions import ProfileNotFound
from botocore.hooks import HierarchicalEmitter
from dateutil.tz import tzlocal

import awscli_plugin_credential_mfa as awscli_plugin


@pytest.fixture
def source_credentials():
    yield Credentials('a', 'b', 'c')


@pytest.fixture
def future_time():
    yield datetime.now(tzlocal()) + timedelta(hours=24)


@pytest.fixture
def fake_config():
    return {
        'profiles': {
            'development': {
                'role_arn': 'myrole',
                'source_profile': 'longterm',
                'mfa_serial': 'arn:aws:iam::123456789012:mfa/iam-user@example.com',
            },
            'longterm': {
                'aws_access_key_id': 'akid',
                'aws_secret_access_key': 'skid',
            },
            'non-static': {
                'role_arn': 'myrole',
                'credential_source': 'Environment',
            },
            'chained': {
                'role_arn': 'chained-role',
                'source_profile': 'development',
            },
        },
    }


def create_client_creator(with_response):
    client = mock.Mock()
    if isinstance(with_response, list):
        client.get_session_token.side_effect = with_response
    else:
        client.get_session_token.return_value = with_response
    return mock.Mock(return_value=client)


def create_config_loader(with_config=None):
    if with_config is None:
        with_config = fake_config()
    load_config = mock.Mock()
    load_config.return_value = with_config
    return load_config


def get_expected_creds_from_response(response):
    expiration = response['Credentials']['Expiration']
    if isinstance(expiration, datetime):
        expiration = expiration.isoformat()
    return {
        'access_key': response['Credentials']['AccessKeyId'],
        'secret_key': response['Credentials']['SecretAccessKey'],
        'token': response['Credentials']['SessionToken'],
        'expiry_time': expiration,
    }


def prompter(prompt):
    return '123456'


def test_awscli_initialize__success():
    event_handlers = HierarchicalEmitter()
    awscli_plugin.awscli_initialize(event_handlers)
    session = mock.Mock()

    event_handlers.emit('session-initialized', session=session)

    assert session.get_component.call_args_list == [
        mock.call('credential_provider'),
    ]


def test_inject_mfa_credential_provider__success():
    session = mock.Mock()

    awscli_plugin.inject_mfa_credential_provider(session, event_name='session-initialized')

    assert session.get_component.call_args_list == [
        mock.call('credential_provider'),
    ]

    credential_provider = session.get_component.return_value
    get_provider = credential_provider.get_provider
    assert get_provider.call_args_list == [
        mock.call('env'),
        mock.call('shared-credentials-file'),
        mock.call('config-file'),
    ]

    insert_after = credential_provider.insert_after
    assert insert_after.call_args_list == [
        mock.call('env', mock.ANY),
    ]


def test_inject_mfa_credential_provider__no_profile():
    session = mock.Mock()
    session.get_component.side_effect = ProfileNotFound(profile='unknown')

    awscli_plugin.inject_mfa_credential_provider(session, event_name='session-initialized')

    credential_provider = session.get_component.return_value

    assert not credential_provider.insert_after.called


def test_mfacredentialfetcher__no_cache(future_time, source_credentials):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com'},
        mfa_prompter=prompter,
    )

    expected_response = get_expected_creds_from_response(response)
    response = refresher.fetch_credentials()

    assert response == expected_response


def test_mfacredentialfetcher__datetime(future_time, source_credentials):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time,  # NOTE: no isoformat()
        },
    }
    client_creator = create_client_creator(with_response=response)
    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com'},
        mfa_prompter=prompter,
    )

    expected_response = get_expected_creds_from_response(response)
    response = refresher.fetch_credentials()

    assert response == expected_response


def test_mfacredentialfetcher__retrieves_from_cache(source_credentials):
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'
    cache_key = 'fd031790cd3ad1181b0ebf9d7dfafdba7e760414'
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            },
        },
    }
    client_creator = mock.Mock()
    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com'},
        mfa_prompter=prompter,
        cache=cache,
    )

    expected_response = get_expected_creds_from_response(cache[cache_key])
    response = refresher.fetch_credentials()

    assert response == expected_response
    assert client_creator.call_args_list == []


def test_mfacredentialfetcher__cache_key_is_windows_safe(future_time, source_credentials):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    cache = {}
    client_creator = create_client_creator(with_response=response)

    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com'},
        mfa_prompter=prompter,
        cache=cache,
    )

    refresher.fetch_credentials()

    # On windows, you cannot use a a ':' in the filename, so
    # we need to make sure that it doesn't make it into the cache key.
    cache_key = 'fd031790cd3ad1181b0ebf9d7dfafdba7e760414'

    assert cache_key in cache
    assert cache[cache_key] == response


def test_mfacredentialfetcher__in_cache_but_expired(future_time, source_credentials):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    cache_key = 'fd031790cd3ad1181b0ebf9d7dfafdba7e760414'
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': datetime.now(tzlocal()),
            },
        },
    }

    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com'},
        mfa_prompter=prompter,
        cache=cache,
    )

    expected_response = get_expected_creds_from_response(response)
    response = refresher.fetch_credentials()

    assert response == expected_response


def test_mfacredentialfetcher__durationseconds_can_be_provided(future_time, source_credentials):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)

    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={
            'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com',
            'DurationSeconds': 1234,
        },
        mfa_prompter=prompter,
    )

    refresher.fetch_credentials()

    client = client_creator.return_value
    assert client.get_session_token.call_args_list == [
        mock.call(
            SerialNumber='arn:aws:iam::123456789012:mfa/iam-user@example.com',
            DurationSeconds=1234,
            TokenCode='123456',
        ),
    ]


def test_mfacredentialfetcher__refreshes(future_time, source_credentials):
    responses = [
        {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': (datetime.now(tzlocal()) - timedelta(seconds=100)).isoformat(),
            },
        },
        {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': future_time.isoformat(),
            },
        },
    ]
    client_creator = create_client_creator(with_response=responses)

    refresher = awscli_plugin.MfaCredentialFetcher(
        client_creator,
        source_credentials,
        extra_args={
            'SerialNumber': 'arn:aws:iam::123456789012:mfa/iam-user@example.com',
        },
        mfa_prompter=prompter,
    )

    refresher.fetch_credentials()
    refresher.fetch_credentials()

    client = client_creator.return_value
    assert client.get_session_token.call_args_list == [
        mock.call(
            SerialNumber='arn:aws:iam::123456789012:mfa/iam-user@example.com',
            TokenCode='123456',
        ),
        mock.call(
            SerialNumber='arn:aws:iam::123456789012:mfa/iam-user@example.com',
            TokenCode='123456',
        ),
    ]


def test_mfacredentialprovider__with_no_cache(future_time):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        client_creator,
        cache={},
        profile_name='development',
        prompter=prompter,
    )

    creds = provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


def test_mfacredentialprovider__with_datetime(future_time):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time,  # NOTE: no isoformat()
        },
    }
    client_creator = create_client_creator(with_response=response)
    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        client_creator,
        cache={},
        profile_name='development',
        prompter=prompter,
    )

    creds = provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'


def test_mfacredentialprovider__retrieves_from_cache(future_time):
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'
    cache_key = '5c1ad78c05bbf090feaaac6d4fb6e27e74da17cb'
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            },
        },
    }
    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        mock.Mock(),
        cache=cache,
        profile_name='development',
        prompter=prompter,
    )

    creds = provider.load()

    assert creds.access_key == 'foo-cached'
    assert creds.secret_key == 'bar-cached'
    assert creds.token == 'baz-cached'


def test_mfacredentialprovider__prefers_cache(future_time):
    date_in_future = datetime.utcnow() + timedelta(seconds=1000)
    utc_timestamp = date_in_future.isoformat() + 'Z'
    cache_key = '5c1ad78c05bbf090feaaac6d4fb6e27e74da17cb'
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': utc_timestamp,
            },
        },
    }
    client_creator = create_client_creator([
        Exception('Attempted to call get_session_token when not needed.'),
    ])
    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        client_creator,
        cache=cache,
        profile_name='development',
        prompter=prompter,
    )

    creds = provider.load()

    assert creds.access_key == 'foo-cached'
    assert creds.secret_key == 'bar-cached'
    assert creds.token == 'baz-cached'


def test_mfacredentialprovider__cache_key_is_windows_safe(future_time):
    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': future_time.isoformat(),
        },
    }
    cache = {}
    client_creator = create_client_creator(with_response=response)
    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        client_creator,
        cache=cache,
        profile_name='development',
        prompter=prompter,
    )

    provider.load().get_frozen_credentials()

    cache_key = '5c1ad78c05bbf090feaaac6d4fb6e27e74da17cb'
    assert cache_key in cache
    assert cache[cache_key] == response


def test_mfacredentialprovider__in_cache_but_expired(future_time):
    expired_creds = datetime.now(tzlocal())
    valid_creds = expired_creds + timedelta(hours=1)

    response = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': valid_creds,
        },
    }
    client_creator = create_client_creator(with_response=response)
    cache_key = ''
    cache = {
        cache_key: {
            'Credentials': {
                'AccessKeyId': 'foo-cached',
                'SecretAccessKey': 'bar-cached',
                'SessionToken': 'baz-cached',
                'Expiration': expired_creds,
            },
        },
    }

    provider = awscli_plugin.MfaCredentialProvider(
        create_config_loader(),
        client_creator,
        cache=cache,
        profile_name='development',
        prompter=prompter,
    )

    creds = provider.load()

    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'

    client = client_creator.return_value
    assert client.get_session_token.call_args_list == [
        mock.call(
            SerialNumber='arn:aws:iam::123456789012:mfa/iam-user@example.com',
            TokenCode='123456',
        ),
    ]
