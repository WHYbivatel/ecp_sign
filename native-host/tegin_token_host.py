#!/usr/bin/env python3
"""Tegin token host: prototype of the local component between the extension and a PKCS#11 token.

Prototype for checking the protocol in docs/hardware-tokens.md, not a shipped component. Speaks the
browser Native Messaging framing on stdin/stdout (32-bit native-endian length, UTF-8 JSON). The
private key never leaves the token: the host asks the token to sign the bytes it receives. The PIN
arrives only inside a "sign" message, is passed to C_Login and dropped; it is never logged or echoed.

PKCS#11 modules come only from the installer's allowlist (TEGIN_TOKEN_MODULES, os.pathsep-separated);
a message cannot name a library.
"""
import hashlib
import json
import os
import queue
import struct
import sys
import threading
import time

import PyKCS11
from PyKCS11.LowLevel import CKF_TOKEN_INITIALIZED, CKF_PROTECTED_AUTHENTICATION_PATH, CKF_LOGIN_REQUIRED, CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED

VERSION = 1
HOST = {'name': 'kz.tegin.token', 'version': '0.1.0-prototype'}
MAX_MESSAGE = 64 * 1024
MAX_DATA = 16 * 1024
MECHANISMS = {'RSA-PKCS-SHA256': PyKCS11.CKM_SHA256_RSA_PKCS}
CKR = {
    0x00A0: 'PIN_INCORRECT', 0x00A4: 'PIN_LOCKED', 0x00A2: 'PIN_LEN_RANGE', 0x00A1: 'PIN_INVALID',
    0x00E0: 'TOKEN_REMOVED', 0x0032: 'TOKEN_REMOVED', 0x0003: 'TOKEN_REMOVED', 0x00B3: 'TOKEN_REMOVED', 0x00B0: 'TOKEN_REMOVED',
    0x0050: 'CANCELLED', 0x0070: 'MECHANISM_UNSUPPORTED', 0x0030: 'DEVICE_ERROR', 0x0031: 'DEVICE_ERROR',
}
TEST_PAUSE = float(os.environ.get('TEGIN_TOKEN_HOST_TEST_PAUSE_MS', '0')) / 1000 if os.environ.get('TEGIN_TOKEN_HOST_TEST') == '1' else 0


class HostError(Exception):
    def __init__(self, code, message=''):
        super().__init__(message or code)
        self.code = code


out_lock = threading.Lock()


def send(message):
    body = json.dumps(message, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    with out_lock:
        sys.stdout.buffer.write(struct.pack('=I', len(body)) + body)
        sys.stdout.buffer.flush()


def read():
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return None
    length = struct.unpack('=I', header)[0]
    if length > MAX_MESSAGE:
        raise HostError('BAD_REQUEST', 'message too large')
    body = sys.stdin.buffer.read(length)
    if len(body) < length:
        return None
    return json.loads(body.decode('utf-8'))


def log(event, **fields):
    # Operational log on stderr: operation names and codes only, never PINs, data or signatures.
    sys.stderr.write(json.dumps({'event': event, **fields}, separators=(',', ':')) + '\n')
    sys.stderr.flush()


def b64(data):
    import base64
    return base64.b64encode(bytes(data)).decode('ascii')


def unb64(text, limit):
    import base64
    import binascii
    if not isinstance(text, str) or len(text) > limit * 4 // 3 + 4:
        raise HostError('BAD_REQUEST', 'data')
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error:
        raise HostError('BAD_REQUEST', 'data')


def text(value):
    return value.strip() if isinstance(value, str) else bytes(value).decode('utf-8', 'replace').strip()


class Modules:
    def __init__(self, paths):
        self.libraries = []
        for path in paths:
            library = PyKCS11.PyKCS11Lib()
            try:
                library.load(path)
            except PyKCS11.PyKCS11Error:
                log('module-unavailable', module=os.path.basename(path))
                continue
            self.libraries.append((os.path.basename(path), library))

    # Initialized tokens only: an empty slot or a blank card cannot hold a key.
    def tokens(self):
        for module_index, (name, library) in enumerate(self.libraries):
            for slot in library.getSlotList(tokenPresent=True):
                try:
                    if library.getTokenInfo(slot).flags & CKF_TOKEN_INITIALIZED:
                        yield module_index, name, library, slot
                except PyKCS11.PyKCS11Error:
                    continue


def token_flags(info):
    return {
        'protectedAuthenticationPath': bool(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH),
        'loginRequired': bool(info.flags & CKF_LOGIN_REQUIRED),
        'pinCountLow': bool(info.flags & CKF_USER_PIN_COUNT_LOW),
        'pinFinalTry': bool(info.flags & CKF_USER_PIN_FINAL_TRY),
        'pinLocked': bool(info.flags & CKF_USER_PIN_LOCKED),
    }


def certificates(session):
    found = []
    for handle in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
        value, key_id, label = session.getAttributeValue(handle, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID, PyKCS11.CKA_LABEL])
        if not value or not key_id:
            continue
        der = bytes(value)
        found.append({'keyId': bytes(key_id).hex(), 'label': text(label or b''), 'certificate': b64(der), 'sha256': hashlib.sha256(der).hexdigest()})
    return found


class Host:
    def __init__(self, modules):
        self.modules = modules
        self.jobs = queue.Queue()
        self.cancelled = set()
        self.current = None
        self.lock = threading.Lock()

    def hello(self, message):
        return {'host': HOST, 'protocol': VERSION, 'modules': [name for name, _ in self.modules.libraries], 'mechanisms': sorted(MECHANISMS)}

    def list(self, message):
        tokens = []
        for module_index, name, library, slot in self.modules.tokens():
            # A token that fails here (removed meanwhile, unreadable card) is left out of the list.
            try:
                info = library.getTokenInfo(slot)
                session = library.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
                try:
                    certs = certificates(session)
                finally:
                    session.closeSession()
            except PyKCS11.PyKCS11Error as error:
                log('token-skipped', op='list', ckr=hex(getattr(error, 'value', 0) or 0))
                continue
            tokens.append({'module': module_index, 'moduleName': name, 'slot': int(slot), 'label': text(info.label), 'manufacturer': text(info.manufacturerID),
                           'model': text(info.model), 'serial': text(info.serialNumber), 'flags': token_flags(info), 'certificates': certs})
        return {'tokens': tokens}

    def check_cancel(self, request_id):
        with self.lock:
            if request_id in self.cancelled:
                self.cancelled.discard(request_id)
                raise HostError('CANCELLED')

    def sign(self, message):
        request_id = message['id']
        mechanism = MECHANISMS.get(message.get('mechanism'))
        if mechanism is None:
            raise HostError('MECHANISM_UNSUPPORTED')
        data = unb64(message.get('data'), MAX_DATA)
        target = next(((library, slot) for index, _, library, slot in self.modules.tokens()
                       if index == message.get('module') and int(slot) == message.get('slot')), None)
        if target is None:
            raise HostError('TOKEN_REMOVED')
        library, slot = target
        info = library.getTokenInfo(slot)
        # The token and certificate chosen by the user must still be the ones present: a removed and
        # re-inserted or swapped token is refused instead of signing with another key.
        if text(info.serialNumber) != message.get('serial'):
            raise HostError('TOKEN_REMOVED')
        flags = token_flags(info)
        if flags['pinLocked']:
            raise HostError('PIN_LOCKED')
        pin = message.get('pin')
        if not flags['protectedAuthenticationPath'] and (not isinstance(pin, str) or not pin):
            raise HostError('PIN_REQUIRED')
        session = library.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
        try:
            chosen = next((cert for cert in certificates(session) if cert['keyId'] == message.get('keyId') and cert['sha256'] == message.get('certificateSha256')), None)
            if chosen is None:
                raise HostError('KEY_NOT_FOUND')
            if TEST_PAUSE:
                time.sleep(TEST_PAUSE)
            self.check_cancel(request_id)
            # A protected authentication path (PIN pad) takes the PIN on the device: C_Login with no PIN.
            session.login(None if flags['protectedAuthenticationPath'] else pin)
            pin = None
            message['pin'] = None
            try:
                self.check_cancel(request_id)
                keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, bytes.fromhex(chosen['keyId']))])
                if not keys:
                    raise HostError('KEY_NOT_FOUND')
                signature = session.sign(keys[0], data, PyKCS11.Mechanism(mechanism, None))
            finally:
                try:
                    session.logout()
                except PyKCS11.PyKCS11Error:
                    pass
        finally:
            try:
                session.closeSession()
            except PyKCS11.PyKCS11Error:
                pass
        return {'signature': b64(signature)}

    def cancel(self, message):
        target = message.get('target')
        with self.lock:
            if self.current == target or any(job.get('id') == target for job in list(self.jobs.queue)):
                self.cancelled.add(target)
                return {'cancelled': True}
        return {'cancelled': False}

    def run_job(self, message):
        request_id = message.get('id')
        op = message.get('op')
        try:
            with self.lock:
                self.current = request_id
            self.check_cancel(request_id)
            result = {'list': self.list, 'sign': self.sign}[op](message)
            send({'v': VERSION, 'id': request_id, 'ok': True, **result})
            log('done', op=op)
        except HostError as error:
            send({'v': VERSION, 'id': request_id, 'ok': False, 'code': error.code})
            log('refused', op=op, code=error.code)
        except PyKCS11.PyKCS11Error as error:
            code = CKR.get(getattr(error, 'value', None), 'TOKEN_ERROR')
            send({'v': VERSION, 'id': request_id, 'ok': False, 'code': code})
            log('token-error', op=op, code=code, ckr=hex(getattr(error, 'value', 0) or 0))
        finally:
            message.pop('pin', None)
            with self.lock:
                self.current = None
                self.cancelled.discard(request_id)

    def worker(self):
        while True:
            message = self.jobs.get()
            if message is None:
                return
            self.run_job(message)

    def handle(self, message):
        if not isinstance(message, dict) or message.get('v') != VERSION or not isinstance(message.get('id'), str) or len(message['id']) > 64:
            raise HostError('BAD_REQUEST', 'envelope')
        allowed = {'hello': {'v', 'id', 'op'}, 'list': {'v', 'id', 'op'}, 'cancel': {'v', 'id', 'op', 'target'},
                   'sign': {'v', 'id', 'op', 'module', 'slot', 'serial', 'keyId', 'certificateSha256', 'mechanism', 'data', 'pin'}}
        op = message.get('op')
        if op not in allowed or set(message) - allowed[op]:
            raise HostError('BAD_REQUEST', 'fields')
        if op == 'hello':
            send({'v': VERSION, 'id': message['id'], 'ok': True, **self.hello(message)})
        elif op == 'cancel':
            result = self.cancel(message)
            send({'v': VERSION, 'id': message['id'], 'ok': True, **result})
            log('cancel', found=result['cancelled'])
        else:
            if self.jobs.qsize() >= 4:
                raise HostError('BUSY')
            self.jobs.put(message)


def main():
    paths = [path for path in os.environ.get('TEGIN_TOKEN_MODULES', '').split(os.pathsep) if path]
    host = Host(Modules(paths))
    thread = threading.Thread(target=host.worker, daemon=True)
    thread.start()
    while True:
        try:
            message = read()
        except (HostError, ValueError) as error:
            send({'v': VERSION, 'id': None, 'ok': False, 'code': getattr(error, 'code', 'BAD_REQUEST')})
            continue
        if message is None:
            break
        try:
            host.handle(message)
        except HostError as error:
            send({'v': VERSION, 'id': message.get('id') if isinstance(message, dict) and isinstance(message.get('id'), str) else None, 'ok': False, 'code': error.code})
            log('refused', op=message.get('op') if isinstance(message, dict) else None, code=error.code)
    host.jobs.put(None)
    thread.join(timeout=5)


if __name__ == '__main__':
    main()
