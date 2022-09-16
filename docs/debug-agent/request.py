#!/usr/bin/env python3

import jwt, requests, base64, yaml, toml

with open("agent-config.toml", "r") as fp:
    config = toml.load(fp)

url = f"http://{config['bind-address']}:{config['bind-port']}/v1/apply"
headers = {
    "Content-Type": "application/jwt"
}

with open("request.yaml", "r") as fp:
    payload = yaml.safe_load(fp)

data = jwt.encode(payload, base64.b64decode(config["shared-secret"]))
r = requests.post(url, headers=headers, data=data)

print("Status code:", r.status_code)
print(r.text)
