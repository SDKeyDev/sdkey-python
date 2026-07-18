"""Minimal usage example. Replace placeholders with values from the SDKey dashboard.

    python -m pip install -e .
    python examples/basic.py
"""

from __future__ import annotations

import os
import sys

from sdkey import SdkeyClient, SdkeyError

client = SdkeyClient(
    api_base_url=os.environ.get("SDKEY_API_BASE_URL", "https://api.sdkey.dev"),
    app_id=os.environ.get("SDKEY_APP_ID", "00000000-0000-0000-0000-000000000000"),
    app_public_key_b64=os.environ.get("SDKEY_APP_PUBLIC_KEY_B64", ""),
)


def main() -> None:
    license_key = os.environ.get("SDKEY_LICENSE_KEY", "SDKY-XXXX-XXXX-XXXX-XXXX")
    hwid = os.environ.get("SDKEY_HWID", "example-machine-1")

    try:
        result = client.validate(license_key, hwid)
        print(result)
    except SdkeyError as err:
        print(f"[{err.code}] {err.message}", file=sys.stderr)
        raise SystemExit(1) from err


if __name__ == "__main__":
    main()
