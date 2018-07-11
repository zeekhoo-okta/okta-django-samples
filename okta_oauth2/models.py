# Create your models here.
from __future__ import unicode_literals
from django.conf import settings
# from django.db import models
import requests


class Config:
    # Configuration object
    org_url = settings.ORG_URL

    # OpenID Specific
    grant_type = 'authorization_code'
    client_id = settings.CLIENT_ID
    client_secret = settings.CLIENT_SECRET
    issuer = settings.ISSUER
    scopes = settings.SCOPES
    redirect_uri = settings.REDIRECT_URI


class DiscoveryDocument:
    # Find the OIDC metadata through discovery
    def __init__(self, issuer_uri):
        r = requests.get(issuer_uri + "/.well-known/openid-configuration")
        self.json = r.json()

    def getJson(self):
        return self.json


class TokenManager:
    def __init__(self):
        self.idToken = None
        self.accessToken = None
        self.claims = None

    def set_id_token(self, token):
        self.idToken = token

    def set_access_token(self, token):
        self.accessToken = token

    def set_claims(self, claims):
        self.claims = claims

    def getJson(self):
        response = {}
        if self.idToken:
            response['idToken'] = self.idToken

        if self.accessToken:
            response['accessToken'] = self.accessToken

        if self.claims:
            response['claims'] = self.claims
        return response
