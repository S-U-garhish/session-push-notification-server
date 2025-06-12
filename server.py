import signal
import urllib3
import resource
import json
import os

from flask import Flask, request, jsonify, abort
from flask_httpauth import HTTPBasicAuth
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.platform.asyncio import AsyncIOMainLoop

from pushNotificationHandler import PushNotificationHelperV2
from const import *
from lokiLogger import LokiLogger
from utils import decrypt, encrypt, make_symmetric_key, onion_request_data_handler, onion_request_v4_data_handler
from databaseHelperV2 import DatabaseHelperV2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from base64 import b64decode
import asyncio
#from observer import Observer

resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
urllib3.disable_warnings()


def handle_exit(sig, frame):
    PN_helper_v2.stop()
    #observer.stop()
    database_helper.flush()
    loop.stop()
    raise SystemExit
def get_server_priv():
    if os.path.exists(PRIVKEY_FILE):
        with open(PRIVKEY_FILE, "r") as f:
            key = f.read()
            if key[-1] == '\n':
                key = key[:-1]
            if len(key) != 64:
                raise RuntimeError(
                    "Invalid key_x25519: expected 64 bytes, not {} bytes".format(len(key))
                )
        server_privkey_bytes = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(key))
        return server_privkey_bytes
    else:
        raise Exception('Could not find privkey file')

app = Flask(__name__)
auth = HTTPBasicAuth()
#password_hash = generate_password_hash("w3b)W64#45BWh&UNSR#Tn_s?")  # your password
logger = LokiLogger().logger
#observer = Observer(logger)
database_helper = DatabaseHelperV2()
loop = IOLoop.instance()
signal.signal(signal.SIGTERM, handle_exit)
server_private_key = get_server_priv()

# PN approach V2 #
PN_helper_v2 = PushNotificationHelperV2(logger, database_helper, None)

@app.route('/register', methods=[POST])
def register_v2():
    args = receive_encrypted_body(request)
    device_token = None
    session_id = None
    if TOKEN in args:
        device_token = args[TOKEN]
    if PUBKEY in args:
        session_id = args[PUBKEY]

    if device_token and session_id:
        PN_helper_v2.register(device_token, session_id)
        return jsonify({CODE: 1, MSG: SUCCESS, "subResponses": [
            {"success": True}
            ]})
    else:
        logger.info("Onion routing register error")
        raise Exception(PARA_MISSING)

@app.route('/unregister', methods=[POST])
def unregister():
    args = receive_encrypted_body(request)
    device_token = None
    if TOKEN in args:
        device_token = args[TOKEN]

    if device_token:
        session_id = PN_helper_v2.unregister(device_token)
        if session_id:
            return jsonify({CODE: 1, MSG: SUCCESS, "subResponses": [
            {"success": True}
            ]})
        else:
            return jsonify({CODE: 1, MSG: SUCCESS, "subResponses": [
            {"success": False}
            ]})
    else:
        logger.info("Onion routing unregister error")
        raise Exception(PARA_MISSING)

@app.route('/subscribe_closed_group', methods=[POST])
def subscribe_closed_group():
    args = receive_encrypted_body(request)
    closed_group_id = None
    session_id = None
    if PUBKEY in args:
        session_id = args[PUBKEY]
    if CLOSED_GROUP in args:
        closed_group_ids = args[CLOSED_GROUP]
    if TOKEN in args:
        device_token = args[TOKEN]

    if session_id and device_token:
        PN_helper_v2.register(device_token, session_id)
        for closed_group_id in closed_group_ids:
            PN_helper_v2.subscribe_closed_group(closed_group_id, session_id)
        return jsonify({CODE: 1, MSG: SUCCESS, "subResponses": [
            {"success": True, "error":0, "message": "Subscribed to closed group successfully."},]}
        )
    else:
        logger.info("Onion routing subscribe closed group error")
        raise Exception(PARA_MISSING)

@app.route('/unsubscribe_closed_group', methods=[POST])
def unsubscribe_closed_group():
    args = receive_encrypted_body(request)
    closed_group_id = None
    session_id = None
    if PUBKEY in args:
        session_id = args[PUBKEY]
    if CLOSED_GROUP in args:
        closed_group_ids = args[CLOSED_GROUP]

    if closed_group_ids and session_id:
        for closed_group_id in closed_group_ids:
            closed_group = PN_helper_v2.subscribe_closed_group(closed_group_id, session_id)
        if closed_group:
            return jsonify({CODE: 1, MSG: SUCCESS, "subResponses": [
            {
                "success": True, "error":0, "message": "Subscribed to closed group successfully."
            },]}
        )
        else:
            return jsonify({CODE: 0, MSG: SUCCESS, subResponses: [
            {
                "success": False, "error":1, "message": "Subscribed to closed group successfully."
            },]}
        )
    else:
        logger.info("Onion routing unsubscribe closed group error")
        raise Exception(PARA_MISSING)

@app.route('/notify', methods=[POST])
def notify():
    args = receive_encrypted_body(request)
    session_id = None
    data = None
    if SEND_TO in args:
        session_id = args[SEND_TO]
    if DATA in args:
        data = args[DATA]

    if session_id and data:
        logger.info('Notify to ' + session_id)
        PN_helper_v2.add_message_to_queue(args)
        return jsonify({CODE: 1, MSG: SUCCESS})
    else:
        raise Exception(PARA_MISSING)


Routing = {'register': register_v2,
           'unregister': unregister,
           'subscribe_closed_group': subscribe_closed_group,
           'unsubscribe_closed_group': unsubscribe_closed_group,
           'notify': notify}


def receive_encrypted_body(request):
    try:
        json_data = request.get_json()

        ephemeral_public_key_b64 = json_data["ephemeralPublicKey"]
        sealed_box_b64 = json_data["sealedBox"]

        # Base64デコード
        client_public_key_bytes = b64decode(ephemeral_public_key_b64)
        sealed_box_bytes = b64decode(sealed_box_b64)

        # クライアントの公開鍵オブジェクトを生成
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_key_bytes)

        # 鍵交換で共有秘密を導出
        shared_secret = server_private_key.exchange(client_public_key)

        # 共通鍵をHKDFから導出（saltとinfoはSwiftと同じにする必要がある）
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"",            # Swift側と一致させる
            info=b"",            # Swift側と一致させる
        ).derive(shared_secret)

        # SealedBoxを復号
        nonce = sealed_box_bytes[:12]
        ciphertext = sealed_box_bytes[12:]

        chacha = ChaCha20Poly1305(symmetric_key)
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data=None)
        #logger.info(plaintext)
        return json.loads(plaintext.decode('utf-8'))

    except Exception as e:
        logger.info(e)
        return {
            "status": "error",
            "message": str(e)
        }

def onion_request_body_handler(body):
    ciphertext = None
    ephemeral_pubkey = None
    symmetric_key = None
    response = json.dumps({STATUS: 400,
                           BODY: {CODE: 0,
                                  MSG: PARA_MISSING}})
    if CIPHERTEXT in body:
        ciphertext = body[CIPHERTEXT]
    if EPHEMERAL in body:
        ephemeral_pubkey = body[EPHEMERAL]

    if ephemeral_pubkey:
        symmetric_key = make_symmetric_key(ephemeral_pubkey)
    else:
        logger.error("Client public key is None.")
        logger.error(f"This request is from {request.environ.get('HTTP_X_REAL_IP')}.")
        abort(400)

    if ciphertext and symmetric_key:
        try:
            parameters = json.loads(decrypt(ciphertext, symmetric_key).decode('utf-8'))
            args = json.loads(parameters['body'])
            if debug_mode:
                logger.info(parameters)
            func = Routing[parameters['endpoint']]
            code, message = func(args)
            response = json.dumps({STATUS: 200,
                                   BODY: {CODE: code,
                                          MSG: message}})
        except Exception as e:
            logger.error(e)
            response = json.dumps({STATUS: 400,
                                   BODY: {CODE: 0,
                                          MSG: str(e)}})
    else:
        logger.error("Ciphertext or symmetric key is None.")
        abort(400)
    return jsonify({RESULT: encrypt(response, symmetric_key)})

"""
@app.route('/loki/v2/lsrpc', methods=[POST])
def onion_request_v2():
    body = {}
    if request.data:
        body = onion_request_data_handler(request.data)
    else:
        logger.error(request.form)
    return onion_request_body_handler(body)
"""
"""
@app.route('/oxen/v4/lsrpc', methods=[POST])
def onion_request_v4():
    junk = None

    try:
        junk = parse_junk(request.data)
    except RuntimeError as e:
        app.logger.warning("Failed to decrypt onion request: {}".format(e))
        abort(http.HTTPStatus.BAD_REQUEST)
    body = {}

    if junk:
        body = onion_request_v4_data_handler(junk)
    else:
        logger.error(request.form)

    v4response = onion_request_v4_body_handler(body)

    return junk.transformReply(v4response)
"""

#@auth.verify_password
#def verify_password(username, password):
#    return check_password_hash(password_hash, password)

"""
@app.route('/get_statistics_data', methods=[POST])
@auth.login_required
def get_statistics_data():
    if auth.current_user():
        start_date = request.json.get(START_DATE)
        end_date = request.json.get(END_DATE)
        total_num_include = request.json.get(TOTAL_MESSAGE_NUMBER)
        ios_pn_num_include = request.json.get(IOS_PN_NUMBER)
        android_pn_num_include = request.json.get(ANDROID_PN_NUMBER)
        closed_group_message_include = request.json.get(CLOSED_GROUP_MESSAGE_NUMBER)
        keys_to_remove = []
        if total_num_include is not None and int(total_num_include) == 0:
            keys_to_remove.append(TOTAL_MESSAGE_NUMBER)
        if ios_pn_num_include is not None and int(ios_pn_num_include) == 0:
            keys_to_remove.append(IOS_PN_NUMBER)
        if android_pn_num_include is not None and int(android_pn_num_include) == 0:
            keys_to_remove.append(ANDROID_PN_NUMBER)
        if closed_group_message_include is not None and int(closed_group_message_include) == 0:
            keys_to_remove.append(CLOSED_GROUP_MESSAGE_NUMBER)

        data = database_helper.get_stats_data(start_date, end_date)
        for item in data:
            for key in keys_to_remove:
                item.pop(key, None)
        return jsonify({CODE: 0,
                        DATA: data})
"""
async def main():
    await PN_helper_v2.run()

    try:
        # サンプル: 永続的に実行
        while True:
            await asyncio.sleep(60)
    except KeyboardInterrupt:
        await PN_helper_v2.stop()
if __name__ == '__main__':
    database_helper.populate_cache()

    # Tornado を asyncio のイベントループに接続
    AsyncIOMainLoop().install()

    port = 3000 if debug_mode else 5000
    http_server = HTTPServer(WSGIContainer(app), no_keep_alive=True)
    http_server.listen(port)

    # asyncio.run() は使わず、get_event_loop() から直接 run
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()  # Webサーバーが続くように
