# SplitSig Test Vectors

Independent verification of the key derivation — no service or demo needed.

## Derivation

```
privkey = SHA256( ecdsa_signature || nonce )
pubkey  = privkey * G  (secp256k1, x-only)
```

## Inputs

```
signature (hex):
3045022100a3f3c5e7b2d8f1a9c4e6b0d7f2a8e5c1b3d9f0a7c2e4
d6b8a0f1c3e5d7a9b2022054e8c1a3f5d7b9e0c2a4f6d8b0e3c5a7
f9d1b3e5c7a9f0d2b4e6c8a0f2d4e6b8

nonce (hex):
deadbeef0102030405060708091011121314151617181920212223
2425262728
```

## Expected Results

| Input | SHA256 | Matches privkey? |
|-------|--------|-----------------|
| sig + nonce | `41373b36f9b4620864580f290b2fa1da0f0fa7293d34feff5047969051196bf7` | **yes** |
| sig only | `5c6d174e01cb2cbc83d6b049f6bb8fdb4e5a69843747061c5fc39ce89dfc35ce` | no |
| nonce only | `4e37f2f66519dfd4dd2e475b5c59405c2637e53327472cd5f5ac55372bbf2648` | no |

All three outputs are different. The server (which has only the signature) and a thief (who has only the recovery kit with the nonce) each derive a different, wrong key.

## Verify Yourself

```bash
# SHA256(sig + nonce) — the correct derived key
echo -n "3045022100a3f3c5e7b2d8f1a9c4e6b0d7f2a8e5c1b3d9f0a7c2e4d6b8a0f1c3e5d7a9b2022054e8c1a3f5d7b9e0c2a4f6d8b0e3c5a7f9d1b3e5c7a9f0d2b4e6c8a0f2d4e6b8deadbeef01020304050607080910111213141516171819202122232425262728" \
  | xxd -r -p | sha256sum
# Expected: 41373b36f9b4620864580f290b2fa1da0f0fa7293d34feff5047969051196bf7

# SHA256(sig only) — what the server could compute
echo -n "3045022100a3f3c5e7b2d8f1a9c4e6b0d7f2a8e5c1b3d9f0a7c2e4d6b8a0f1c3e5d7a9b2022054e8c1a3f5d7b9e0c2a4f6d8b0e3c5a7f9d1b3e5c7a9f0d2b4e6c8a0f2d4e6b8" \
  | xxd -r -p | sha256sum
# Expected: 5c6d174e01cb2cbc83d6b049f6bb8fdb4e5a69843747061c5fc39ce89dfc35ce

# SHA256(nonce only) — what a stolen recovery kit gives
echo -n "deadbeef01020304050607080910111213141516171819202122232425262728" \
  | xxd -r -p | sha256sum
# Expected: 4e37f2f66519dfd4dd2e475b5c59405c2637e53327472cd5f5ac55372bbf2648
```

```python
import hashlib
sig = bytes.fromhex("3045022100a3f3c5e7b2d8f1a9c4e6b0d7f2a8e5c1b3d9f0a7c2e4d6b8a0f1c3e5d7a9b2022054e8c1a3f5d7b9e0c2a4f6d8b0e3c5a7f9d1b3e5c7a9f0d2b4e6c8a0f2d4e6b8")
nonce = bytes.fromhex("deadbeef01020304050607080910111213141516171819202122232425262728")
print("privkey:", hashlib.sha256(sig + nonce).hexdigest())
# Expected: 41373b36f9b4620864580f290b2fa1da0f0fa7293d34feff5047969051196bf7
```

## Checklist

- [ ] SHA256(sig + nonce) matches expected value in three environments
- [ ] SHA256(sig) alone produces a different value
- [ ] SHA256(nonce) alone produces a different value
- [ ] The derived privkey is a valid secp256k1 scalar (< curve order n)
