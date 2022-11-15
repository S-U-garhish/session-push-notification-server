import signal
import urllib3
import resource
import json
import http

from flask import Flask, request, jsonify, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from pushNotificationHandler import PushNotificationHelperV2
from const import *
from lokiLogger import LokiLogger
from utils import decrypt, encrypt, make_symmetric_key, onion_request_data_handler, onion_request_v4_data_handler
from databaseHelperV2 import DatabaseHelperV2
from observer import Observer
from crypto import parse_junk

resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
urllib3.disable_warnings()


def handle_exit(sig, frame):
    PN_helper_v2.stop()
    #observer.stop()
    database_helper.flush()
    loop.stop()
    raise SystemExit


app = Flask(__name__)
auth = HTTPBasicAuth()
password_hash = generate_password_hash("w3b)W64#45BWh&UNSR#Tn_s?")  # your password
logger = LokiLogger().logger
#observer = (logger)
database_helper = DatabaseHelperV2(logger)
loop = IOLoop.instance()
signal.signal(signal.SIGTERM, handle_exit)


# PN approach V2 #
PN_helper_v2 = PushNotificationHelperV2(logger, database_helper, observer=None)


def register_v2(args):
    device_token = None
    session_id = None
    if TOKEN in args:
        device_token = args[TOKEN]
    if PUBKEY in args:
        session_id = args[PUBKEY]

    if device_token and session_id:
        PN_helper_v2.register(device_token, session_id)
        return 1, SUCCESS
    else:
        logger.info("Onion routing register error")
        raise Exception(PARA_MISSING)


def unregister(args):
    device_token = None
    if TOKEN in args:
        device_token = args[TOKEN]

    if device_token:
        session_id = PN_helper_v2.unregister(device_token)
        if session_id:
            return 1, SUCCESS
        else:
            return 0, "Session id was not registered before."
    else:
        logger.info("Onion routing unregister error")
        raise Exception(PARA_MISSING)


def subscribe_closed_group(args):
    closed_group_id = None
    session_id = None
    if PUBKEY in args:
        session_id = args[PUBKEY]
    if CLOSED_GROUP in args:
        closed_group_id = args[CLOSED_GROUP]

    if closed_group_id and session_id:
        PN_helper_v2.subscribe_closed_group(closed_group_id, session_id)
        return 1, SUCCESS
    else:
        logger.info("Onion routing subscribe closed group error")
        raise Exception(PARA_MISSING)


def unsubscribe_closed_group(args):
    closed_group_id = None
    session_id = None
    if PUBKEY in args:
        session_id = args[PUBKEY]
    if CLOSED_GROUP in args:
        closed_group_id = args[CLOSED_GROUP]

    if closed_group_id and session_id:
        closed_group = PN_helper_v2.unsubscribe_closed_group(closed_group_id, session_id)
        if closed_group:
            return 1, SUCCESS
        else:
            return 0, "Cannot find the closed group id on PN server."
    else:
        logger.info("Onion routing unsubscribe closed group error")
        raise Exception(PARA_MISSING)


def notify(args):
    session_id = None
    data = None
    if SEND_TO in args:
        session_id = args[SEND_TO]
    if DATA in args:
        data = args[DATA]

    if session_id and data:
        logger.info('Notify to ' + session_id)
        PN_helper_v2.add_message_to_queue(args)
        return 1, SUCCESS
    else:
        raise Exception(PARA_MISSING)


Routing = {'register': register_v2,
           'unregister': unregister,
           'subscribe_closed_group': subscribe_closed_group,
           'unsubscribe_closed_group': unsubscribe_closed_group,
           'notify': notify}


def onion_request_v4_body_handler(parameters):
    try:
        endpoint = parameters['endpoint']
        if endpoint.startswith('/'):
            endpoint = endpoint[1:]

        if debug_mode:
            logger.info(parameters)
        func = Routing[endpoint]
        code, message = func(parameters)
        body = json.dumps({CODE: code, MSG: message})
        response = json.dumps({CODE: 200, HEADERS: {'content-type': 'application/json'}})

    except Exception as e:
        logger.error(e)
        body = json.dumps({CODE: 0, MSG: str(e)})
        response = json.dumps({CODE: 400, HEADERS: {'content-type': 'application/json'}})

    v4response = b''.join(
        (b'l', str(len(response)).encode(), b':', response.encode(), str(len(body)).encode(), b':', body.encode(), b'e')
    )
    return v4response


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


@app.route('/loki/v2/lsrpc', methods=[POST])
def onion_request_v2():
    body = {}
    if request.data:
        body = onion_request_data_handler(request.data)
    else:
        logger.error(request.form)
    return onion_request_body_handler(body)


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


@auth.verify_password
def verify_password(username, password):
    return check_password_hash(password_hash, password)


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


if __name__ == '__main__':
    database_helper.populate_cache()
    #observer.run()
    PN_helper_v2.run()
    port = 3000 if debug_mode else 5000
    http_server = HTTPServer(WSGIContainer(app), no_keep_alive=True)
    http_server.listen(port)
    loop.start()
