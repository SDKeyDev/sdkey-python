# sdkey

Official Python client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes. See [PROTOCOL.md](./PROTOCOL.md).

## Install

```bash
pip install sdkey
```

Requires Python 3.10+.

## Quick start

Embed these values from the SDKey dashboard when you ship your app:

```python
from sdkey import SdkeyClient, SdkeyError

client = SdkeyClient(
    api_base_url="https://api.sdkey.dev",
    app_id="YOUR_APP_ID",
    app_public_key_b64="YOUR_APP_PUBLIC_KEY_BASE64",
)

try:
    result = client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", "machine-hwid")
    if result.success:
        print("licensed", result.status, result.expires_at)
    else:
        print("denied", result.code, result.message)
except SdkeyError as err:
    print(err.code, err.message)
    raise
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

## API

### `SdkeyClient(options)`

| Option | Type | Description |
|---|---|---|
| `api_base_url` | `str` | API origin (no trailing slash) |
| `app_id` | `str` | Application UUID |
| `app_public_key_b64` | `str` | Raw Ed25519 public key (32 bytes), base64 |
| `http_post` | callable | Optional HTTP POST override (tests / custom transport) |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key
- `validate(license_key, hwid)` — sealed validate; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `get_session()` / `clear_session()` — inspect or drop the local session

### Errors

Protocol / transport failures raise `SdkeyError` with a `code`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `NETWORK`

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success=False` — they are not raised.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This package is open source; the SDKey server remains a separate product.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
```

## License

MIT
