import json
import os
import requests


def get_cognito_public_keys():
    region = 'us-east-1'
    pool_id = 'us-east-1_s7z41WH1Y'
    url = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"

    resp = requests.get(url)
    return json.dumps(json.loads(resp.text)["keys"][1])