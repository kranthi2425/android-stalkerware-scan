#!/usr/bin/env python3
"""Encrypted iTunes/Finder backup support for ios_scanner.py.

Key derivation (PBKDF2) and keybag parsing use only the standard library. AES itself is not in
the standard library, so decrypting needs ONE optional package: `cryptography` or `pycryptodome`.
Without either, unencrypted backups still work and encrypted ones fail with a clear message.

Format (iOS 10.2 and later), implemented from the public descriptions in iphone-dataprotection /
iphone_backup_decrypt (https://github.com/jsharkey13/iphone_backup_decrypt):
  * Manifest.plist BackupKeyBag is a TLV keybag (4-byte tag, 4-byte big-endian length).
  * Password key = PBKDF2-SHA1(PBKDF2-SHA256(password, DPSL, DPIC), SALT, ITER), 32 bytes.
  * Each class key (WPKY) is AES-wrapped (RFC 3394) with the password key.
  * Manifest.db is AES-256-CBC (zero IV) with the key in ManifestKey (4-byte LE class + wrapped key).
  * Each file's key is in its Manifest.db `file` column (NSKeyedArchiver plist, EncryptionKey).
"""
from __future__ import annotations
import hashlib, plistlib, struct

class CryptoUnavailable(Exception): pass
class WrongPassword(Exception): pass

INSTALL_HINT = ('Decrypting an encrypted backup needs one optional package. Install either:  pip install cryptography  '
                'or  pip install pycryptodome  - then run the scan again. Unencrypted backups never need it.')
WRAP_PASSCODE = 2
_IV0 = b'\x00' * 16

def backend():
    """Return the name of an available AES backend, or None."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
        return 'cryptography'
    except ImportError: pass
    try:
        from Crypto.Cipher import AES  # noqa: F401
        return 'pycryptodome'
    except ImportError: return None

class AES:
    """Tiny adapter over whichever optional backend is installed."""
    def __init__(self, name=None):
        self.name = name or backend()
        if not self.name: raise CryptoUnavailable(INSTALL_HINT)

    def ecb_decrypt(self, key, block):
        if self.name == 'cryptography':
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            d = Cipher(algorithms.AES(key), modes.ECB()).decryptor(); return d.update(block) + d.finalize()
        from Crypto.Cipher import AES as A
        return A.new(key, A.MODE_ECB).decrypt(block)

    def ecb_encrypt(self, key, block):
        if self.name == 'cryptography':
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            e = Cipher(algorithms.AES(key), modes.ECB()).encryptor(); return e.update(block) + e.finalize()
        from Crypto.Cipher import AES as A
        return A.new(key, A.MODE_ECB).encrypt(block)

    def cbc_decryptor(self, key, iv=_IV0):
        """Return a function that decrypts successive 16-byte-aligned chunks."""
        if self.name == 'cryptography':
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update
        from Crypto.Cipher import AES as A
        return A.new(key, A.MODE_CBC, iv).decrypt

    def cbc_encryptor(self, key, iv=_IV0):
        if self.name == 'cryptography':
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update
        from Crypto.Cipher import AES as A
        return A.new(key, A.MODE_CBC, iv).encrypt

def aes_unwrap(aes, kek, wrapped):
    """RFC 3394 AES key unwrap. Raises WrongPassword when the integrity check fails."""
    n = len(wrapped) // 8 - 1
    if n < 1 or len(wrapped) % 8: raise ValueError('bad wrapped key length')
    a = wrapped[:8]; r = [wrapped[8 * i:8 * i + 8] for i in range(1, n + 1)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = struct.pack('>Q', struct.unpack('>Q', a)[0] ^ (n * j + i))
            b = aes.ecb_decrypt(kek, t + r[i - 1]); a, r[i - 1] = b[:8], b[8:]
    if a != b'\xa6' * 8: raise WrongPassword('AES key unwrap integrity check failed')
    return b''.join(r)

def aes_wrap(aes, kek, key):
    """RFC 3394 AES key wrap (used by tests to build synthetic encrypted backups)."""
    n = len(key) // 8; a = b'\xa6' * 8; r = [key[8 * i:8 * i + 8] for i in range(n)]
    for j in range(6):
        for i in range(1, n + 1):
            b = aes.ecb_encrypt(kek, a + r[i - 1])
            a = struct.pack('>Q', struct.unpack('>Q', b[:8])[0] ^ (n * j + i)); r[i - 1] = b[8:]
    return a + b''.join(r)

def tlv(blob):
    i = 0
    while i + 8 <= len(blob):
        tag, ln = blob[i:i + 4], struct.unpack('>L', blob[i + 4:i + 8])[0]
        yield tag, blob[i + 8:i + 8 + ln]; i += 8 + ln

class Keybag:
    def __init__(self, blob):
        self.attrs, self.classes, cur = {}, {}, None
        for tag, val in tlv(blob):
            num = struct.unpack('>L', val)[0] if len(val) == 4 else None
            if tag == b'UUID' and b'UUID' not in self.attrs: self.attrs[b'UUID'] = val
            elif tag == b'UUID':
                if cur is not None and b'CLAS' in cur: self.classes[cur[b'CLAS']] = cur
                cur = {b'UUID': val}
            elif cur is not None and tag in (b'CLAS', b'WRAP', b'KTYP'): cur[tag] = num
            elif cur is not None and tag in (b'WPKY', b'PBKY'): cur[tag] = val
            else: self.attrs.setdefault(tag, num if num is not None and tag in (b'VERS', b'TYPE', b'WRAP', b'ITER', b'DPIC', b'DPWT') else val)
        if cur is not None and b'CLAS' in cur: self.classes[cur[b'CLAS']] = cur
        self.keys = {}

    def unlock(self, aes, password):
        pw = password if isinstance(password, bytes) else password.encode('utf-8')
        if b'DPSL' in self.attrs:  # iOS 10.2+: double PBKDF2
            pw = hashlib.pbkdf2_hmac('sha256', pw, self.attrs[b'DPSL'], self.attrs[b'DPIC'], 32)
        key = hashlib.pbkdf2_hmac('sha1', pw, self.attrs[b'SALT'], self.attrs[b'ITER'], 32)
        for cls, ck in self.classes.items():
            if b'WPKY' in ck and (ck.get(b'WRAP', 0) & WRAP_PASSCODE):
                self.keys[cls] = aes_unwrap(aes, key, ck[b'WPKY'])  # raises WrongPassword
        if not self.keys: raise WrongPassword('No class keys could be unlocked')

    def unwrap(self, aes, cls, wrapped):
        if cls not in self.keys: raise KeyError(f'protection class {cls} not unlocked')
        return aes_unwrap(aes, self.keys[cls], wrapped)

def file_record(blob):
    """Parse a Manifest.db `file` column: returns (protection_class, wrapped_key or None, size)."""
    p = plistlib.loads(blob); objs = p['$objects']
    root = objs[p['$top']['root'].data]
    key = None
    ek = root.get('EncryptionKey')
    if ek is not None:
        obj = objs[ek.data] if isinstance(ek, plistlib.UID) else ek
        data = obj.get('NS.data') if isinstance(obj, dict) else obj
        if isinstance(data, (bytes, bytearray)) and len(data) > 4: key = bytes(data[4:])
    return root.get('ProtectionClass'), key, int(root.get('Size') or 0)

def strip_pkcs7(data):
    n = data[-1] if data else 0
    return data[:-n] if 0 < n <= 16 and data.endswith(bytes([n]) * n) else data

def decrypt_stream(aes, key, src, dst, size=None, chunk=1 << 20):
    """Decrypt src file to dst file (AES-256-CBC, zero IV), trimming to size or PKCS7 padding."""
    dec = aes.cbc_decryptor(key)
    with open(src, 'rb') as fi, open(dst, 'wb') as fo:
        tail = b''
        while True:
            buf = fi.read(chunk)
            if not buf: break
            buf = tail + buf; cut = len(buf) - (len(buf) % 16); tail = buf[cut:]
            fo.write(dec(buf[:cut]))
        fo.flush()
    if size is not None and size >= 0:
        with open(dst, 'r+b') as fo: fo.truncate(size)
    else:
        with open(dst, 'rb') as fh: data = fh.read()
        with open(dst, 'wb') as fh: fh.write(strip_pkcs7(data))

def decrypt_bytes(aes, key, data):
    return strip_pkcs7(aes.cbc_decryptor(key)(data[:len(data) - len(data) % 16]))
