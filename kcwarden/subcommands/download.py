import contextlib

import requests
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
    if "KCWARDEN_KEYCLOAK_PASSWORD" in os.environ:
        return os.environ["KCWARDEN_KEYCLOAK_PASSWORD"]
    return getpass("Please enter the password for user {}: ".format(user))


def get_client_secret():
    return os.environ.get("KCWARDEN_CLIENT_SECRET", "")


def get_totp():
    return input("Please enter the TOTP code: ")


def get_token_password_grant(base_url, auth_realm, user, totp_required, client_id="admin-cli", client_secret="pass"):
    password = get_password(user)

    auth_data = {
        "username": user,
        "password": password,
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    if totp_required:
        auth_data["totp"] = get_totp()

    token_url = KC_TOKEN_AUTH.format(base_url, auth_realm)

    req = requests.post(token_url, data=auth_data)
    try:
        json_response = req.json()
    except requests.RequestException:
        raise ValueError(f"Could not parse JSON. Response was: {req.content}")
    if "access_token" not in json_response:
        raise ValueError(f"Did not receive an access token in response. Response was: {json_response}")
    return json_response["access_token"]


def get_token_client_credential_grant(base_url, auth_realm, client_id, client_secret):
    token_url = KC_TOKEN_AUTH.format(base_url, auth_realm)

    req = requests.post(
        token_url, data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    )
    try:
        json_response = req.json()
    except requests.RequestException:
        raise ValueError(f"Could not parse JSON. Response was: {req.content}")
    if "access_token" not in json_response:
        raise ValueError(f"Did not receive an access token in response. Response was: {json_response}")
    return json_response["access_token"]


### Main Loop
def download_config(args: argparse.Namespace):
    # Remove trailing slash on BASE URL, as Keycloak despises them
    base_url = args.base_url.removesuffix("/")

    realm = args.realm
    output_file = args.output
    client_secret = args.client_secret

    if client_secret is None:
        client_secret = get_client_secret()

    if args.auth_method == "password":
        session_token = get_token_password_grant(
            base_url, args.auth_realm, args.user, args.totp, args.client_id, client_secret
        )
    elif args.auth_method == "client":
        session_token = get_token_client_credential_grant(base_url, args.auth_realm, args.client_id, client_secret)
    else:
        print("Unexpected auth_method provided - please file a bug report, this should be impossible")
        return 1

    export = requests.post(
        KC_EXPORT_URL.format(base_url, realm), headers={"Authorization": f"Bearer {session_token}"}
    ).json()

    # TODO Mache ich eigentlich schon was mit Gruppen?
    # export = resolve_composite_roles_for_users(export)

    # If output_file is None, we want to fall back to stdout.
    # stdout should not be closed thus we use `nullcontext`.
    with open(output_file, "w") if output_file else contextlib.nullcontext(sys.stdout) as fo:
        json.dump(export, fo, indent=4)
