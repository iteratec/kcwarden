import contextlib

import requests
from requests.auth import HTTPBasicAuth
import argparse
from getpass import getpass
import os
import json
import sys

# Hardcoded Keycloak URLs
KC_TOKEN_AUTH = "{}/realms/{}/protocol/openid-connect/token"
KC_CLIENT_LIST = "{}/admin/realms/{}/clients/"
KC_GROUP_LIST = "{}/admin/realms/{}/groups/"
KC_GROUP_DETAILS = "{}/admin/realms/{}/groups/{}"
KC_ROLE_LIST = "{}/admin/realms/{}/roles"
KC_ROLE_COMPOSITES = "{}/admin/realms/{}/roles/{}/composites"
KC_CLIENTSCOPE_LIST = "{}/admin/realms/{}/client-scopes/"
KC_CLIENTSCOPE_DETAILS = "{}/admin/realms/{}/client-scopes/{}/scope-mappings/realm"
KC_CLIENTSCOPE_COMPOSITE = "{}/admin/realms/{}/client-scopes/{}/scope-mappings/realm/composite"
KC_EXPORT_URL = "{}/admin/realms/{}/partial-export?exportClients=true&exportGroupsAndRoles=true"


### Network helper functions
def authorized_get(url, token):
    return requests.get(url=url, headers={"Authorization": "Bearer {}".format(token)}).json()


### Authentication-related functions
def get_password(user):
    if "KEYCLOAK_PASSWORD" in os.environ:
        return os.environ["KEYCLOAK_PASSWORD"]
    return getpass("Please enter the password for user {}: ".format(user))


def get_totp():
    return input("Please enter the TOTP code: ")


def get_session(base_url, user, totp_required, auth_realm):
    password = get_password(user)

    auth_data = {"username": user, "password": password, "grant_type": "password"}

    if totp_required:
        auth_data["totp"] = get_totp()

    token_url = KC_TOKEN_AUTH.format(base_url, auth_realm)

    req = requests.post(token_url, auth=HTTPBasicAuth("admin-cli", "pass"), data=auth_data)
    try:
        req.json()
    except requests.RequestException:
        assert False, "Could not parse JSON. Response was: {}".format(req.content)
    assert "access_token" in req.json(), "Did not receive an access token in response. Response was: {}".format(
        req.json()
    )
    return req.json()["access_token"]


### Main Loop
def download_config(args: argparse.Namespace):
    # Remove trailing slash on BASE URL, as Keycloak despises them
    base_url = args.base_url.removesuffix("/")

    realm = args.realm
    output_file = args.output

    session_token = get_session(base_url, args.user, args.totp, args.auth_realm)

    export = requests.post(
        KC_EXPORT_URL.format(base_url, realm), headers={"Authorization": f"Bearer {session_token}"}
    ).json()

    # TODO Mache ich eigentlich schon was mit Gruppen?
    # export = resolve_composite_roles_for_users(export)

    # If output_file is None, we want to fall back to stdout.
    # stdout should not be closed thus we use `nullcontext`.
    with open(output_file, "w") if output_file else contextlib.nullcontext(sys.stdout) as fo:
        json.dump(export, fo, indent=4)
