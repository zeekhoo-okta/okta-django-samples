import requests
import base64


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


def get_logout_endpoint(issuer, id_token, redirect_uri):
    return "{0}/v1/logout?id_token_hint={1}&post_logout_redirect_uri={2}".format(
        issuer, id_token, redirect_uri.split("/oauth2")[0])


def _build_header(config):
    # Builds the header for sending requests

    basic = '{}:{}'.format(config.client_id, config.client_secret)
    authorization_header = base64.b64encode(basic.encode())

    header = {
        'Authorization': 'Basic: ' + authorization_header.decode("utf-8"),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return header
