# sdkey

Official Python client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes, plus plaintext client auth (`register` / `login` / `upgrade`). See [PROTOCOL.md](./PROTOCOL.md).

## Install

```bash
pip install sdkey
```

Requires Python 3.10+.

## Quick start

Embed these values from the SDKey dashboard when you ship your app. `app_version` must **exactly match** the application version configured on the server (`clientVersion`); mismatch returns `APP_OUTDATED`.

```python
from sdkey import SdkeyClient, SdkeyError

client = SdkeyClient(
    api_base_url="https://api.sdkey.dev",
    app_id="YOUR_APP_ID",
    app_version="1.0.0",
    app_public_key_b64="YOUR_APP_PUBLIC_KEY_BASE64",
)

try:
    # hwid is optional (omit for web clients — server skips HWID checks)
    result = client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", "machine-hwid")
    if result.success:
        print("licensed", result.status, result.expires_at, result.subscription_tier)
        print("message", result.message)
    else:
        print("denied", result.code, result.message)
except SdkeyError as err:
    # Init / transport failures use `error` text from the server when present
    print(err.code, err.message)
    raise
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

### Client auth (plaintext JSON)

```python
reg = client.register(
    username="player1",
    password="••••••••",
    license_key="SDKY-XXXX-XXXX-XXXX-XXXX",
    hwid="machine-hwid",  # optional
)
if not reg.success:
    print(reg.code, reg.error)
else:
    print(reg.session_token, reg.user, reg.license)

login = client.login(username="player1", password="••••••••")
upgrade = client.upgrade(username="player1", license_key="SDKY-HIGHER-TIER-KEY")
```

`upgrade` takes **username + license key only** (no password). The new key’s `subscriptionTier` must be strictly greater than the user’s current tier.

## Where `message` vs `error` appears

Per-app `responseMessages` may customize many strings. The SDK surfaces whatever the server returns.

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` (raised as `SdkeyError.message`) |
| Sealed validate | `message` | `message` |
| Client register / login / upgrade | *(none)* | `error` on `ClientAuthResult` |

### Example JSON shapes

**Init failure** (plaintext):

```json
{ "success": false, "error": "Client version outdated", "code": "APP_OUTDATED" }
```

**Sealed validate success** (`message`):

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

**Sealed validate failure** (still `message`, not `error`):

```json
{
  "success": false,
  "code": "HWID_MISMATCH",
  "message": "Hardware ID mismatch",
  "status": null,
  "expiresAt": null,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

**Client auth failure** (`error`):

```json
{
  "success": false,
  "error": "License tier must be higher than the current tier",
  "code": "TIER_NOT_HIGHER"
}
```

## API

### `SdkeyClient(options)`

| Option | Type | Description |
|---|---|---|
| `api_base_url` | `str` | API origin (no trailing slash) |
| `app_id` | `str` | Application UUID |
| `app_version` | `str` | Exact app version → sent as `clientVersion` |
| `app_public_key_b64` | `str` | Raw Ed25519 public key (32 bytes), base64 |
| `http_post` | callable | Optional HTTP POST override (tests / custom transport) |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key; sends `clientVersion`
- `validate(license_key, hwid=None)` — sealed validate; omits `hwid` JSON key when not provided; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `register(...)` / `login(...)` / `upgrade(...)` — plaintext `POST /api/v1/client/*`
- `get_session()` / `clear_session()` — inspect or drop the local session

### Errors

Protocol / transport failures raise `SdkeyError` with a `code` and `message` (server `error` text when the API provides one):

`INIT_FAILED` · `APP_OUTDATED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `NETWORK`

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success=False` — they are not raised. Auth denials return `ClientAuthResult(success=False, code=..., error=...)`.

This package does **not** include developer tooling / Bearer (`sdk_live_…`) management APIs.

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
