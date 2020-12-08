# pcapid

An open-source pc API implementation for your self-hosting needs.

## Run server

```sh
pip3 install -r requirements.txt
sanic pcapid.app --host 0.0.0.0 --port 443 --cert cert.pem --key privkey.pem
```

## Client configuration

Add the following to your client configuration:

```plain
api_host = <your_domain>
ws_host = <your_domain>
```
