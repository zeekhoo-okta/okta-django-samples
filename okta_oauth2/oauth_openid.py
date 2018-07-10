import requests
import base64

""" Call /token endpoint
    Returns accessToken, idToken, or both
"""


def call_token_endpoint(url, code, config):
    basic_auth_str = '{0}:{1}'.format(config.client_id, config.client_secret)

    authorization_header = base64.b64encode(basic_auth_str.encode())

    header = {
        'Authorization': 'Basic: ' + authorization_header.decode("utf-8"),
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': config.grant_type,
        'code': str(code),
        'scope': ' '.join(config.scopes),
        'redirect_uri': config.redirect_uri
    }

    # Send token request
    r = requests.post(url, headers=header, params=data)
    response = r.json()

    # Return object
    result = {}
    if 'error' not in response:
        if 'access_token' in response:
            result['access_token'] = response['access_token']
        if 'id_token' in response:
            result['id_token'] = response['id_token']

    return result if len(result.keys()) > 0 else None


def call_userinfo_endpoint(issuer, token):
    # Calls /userinfo endpoint with a valid access_token to fetch user information scoped to the access token

    header = {'Authorization': 'Bearer {}'.format(token)}
    r = requests.get("{}/v1/userinfo".format(issuer), headers=header)

    if r.status_code != 401:
        # Success
        return r.json()
    return


def call_introspect(issuer, token, config):
    # Calls /introspect endpoint to check if accessToken is valid

    header = _build_header(config)
    data = {'token': token}
    r = requests.post("{}/v1/introspect".format(issuer), headers=header, params=data)
    print(r)

    if r.status_code != 401:
        # Success
        return r.json()
    else:
        # Error
        print(r.json())
        return


def call_revocation(issuer, token, config):
    # Calls /revocation endpoint to revoke current accessToken
    header = _build_header(config)
    data = {'token': token}
    r = requests.post("{}/v1/revoke".format(issuer), headers=header, params=data)
    print(r)
    if r.status_code == 204:
        return
    else:
        return r.status_code


def _build_header(config):
    # Builds the header for sending requests

    basic = '{}:{}'.format(config.client_id, config.client_secret)
    authorization_header = base64.b64encode(basic.encode())

    header = {
        'Authorization': 'Basic: ' + authorization_header.decode("utf-8"),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return header
