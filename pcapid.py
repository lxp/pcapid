import secrets
import string

from sanic import Sanic
from sanic.exceptions import abort
from sanic.request import json_loads
from sanic.response import file, json, json_dumps


class Peer(object):
    def __init__(self):
        self.infos = False
        self.connected = False


peers = {}
sessions = {}
app = Sanic(__name__)


def build_message(action, payload):
    return {
        'version': 1,
        'action': action,
        'payload': payload,
    }


async def send_message(peer_id, message):
    print('Sent(%s): %s' % (peer_id, message))
    return await peers[peer_id].ws.send(json_dumps(message))


def rand_string(length):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@app.websocket('/')
async def websocket(request, ws):
    print(request.args)

    session_id = request.args['session_id'][0]

    if session_id not in sessions:
        abort(401)

    peer_id = sessions[session_id]
    peer = peers[peer_id]
    peer.build = request.args['build'][0] or None
    peer.sdk_version = request.args['sdk_version'][0] or None
    peer.ws = ws

    if peer.infos:
        peer.connected = True

    try:
        while True:
            data = await ws.recv()
            await handle_data(peer_id, peer, json_loads(data))
    finally:
        peer.connected = False
        peer.ws = None


async def handle_data(peer_id, peer, data):
    print('Received(%s): %s' % (peer_id, data))

    if data['version'] != 1:
        return

    action = data['action']
    if action == 'conn_update':
        peer.mode = data['payload']['mode']
        peer.name = data['payload']['name']
        peer.desc = data['payload']['desc']
        peer.game_id = data['payload']['game_id']
        peer.secret = data['payload']['secret']
        peer.max_players = data['payload']['max_players']
        peer.players = data['payload']['players']
        peer.public = data['payload']['public']
        peer.guests = data['payload']['guests']
        peer.infos = True
        peer.connected = True

    elif action == 'offer':
        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
            'user': {
                'id': 0,
                'name': 'pcapid',
                'external_id': '',
                'external_provider': '',
            },
            'is_owner': True,
            'permissions': {
                'gamepad': True,
                'keyboard': True,
                'mouse': True,
            },
            'skip_approval': True,
        })
        await send_message(payload['to'], build_message('offer_relay', payload))

    elif action == 'answer':
        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(payload['to'], build_message('answer_relay', payload))

    elif action == 'candex':
        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(payload['to'], build_message('candex_relay', payload))

    elif action == 'offer_cancel':
        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(payload['to'], build_message('offer_cancel_relay', payload))

    elif action == 'client_disconnect':
        peer.connected = False

    else:
        print('Unknown action: %s' % data.action)


@app.route('/source')
async def source(request):
    return await file(__file__)


@app.route('/me')
async def me(request):
    session_id = request.token
    if session_id not in sessions:
        abort(401)

    user_data = {
        'id': 0,
        'name': 'pcapid',
        'email': 'pc@api.d',
        'warp': False,
        'staff': False,
        'team_id': '',
        'is_saml': False,
        'app_config': {},
    }
    return json({'data': user_data})


@app.route('/v1/auth', methods=['POST'])
async def auth(request):
    peer_id = rand_string(28)
    session_id = secrets.token_hex(32)
    peers[peer_id] = Peer()
    sessions[session_id] = peer_id
    data = {
        'instance_id': '',
        'user_id': 0,
        'session_id': session_id,
        'host_peer_id': peer_id,
    }
    return json(data, status=201)


@app.route('/v2/hosts')
async def hosts(request):
    session_id = request.token
    if session_id not in sessions:
        abort(401)

    peer_id = sessions[session_id]

    hosts = []
    for remote_peer_id, peer in peers.items():
        if peer.connected:
            hosts.append({
                'user': {
                    'id': 0,
                    'name': 'pcapid',
                    'warp': False,
                    'external_id': '',
                    'external_provider': '',
                    'team_id': '',
                },
                'peer_id': remote_peer_id,
                'game_id': peer.game_id,
                'build': peer.build,
                'description': peer.desc,
                'max_players': peer.max_players,
                'mode': peer.mode,
                'name': peer.name,
                'players': peer.players,
                'public': peer.public,
                'self': remote_peer_id == peer_id,
            })

    data = {
        'data': hosts,
        'has_more': False,
    }
    return json(data)


@app.route('/friend-requests')
async def friend_requests(request):
    session_id = request.token
    if session_id not in sessions:
        abort(401)

    data = {
        'data': [],
        'has_more': False,
    }
    return json(data)


@app.route('/exit-codes', methods=['PUT'])
async def exit_codes(request):
    return json('connection metric not found')


@app.route('/metrics', methods=['PUT'])
async def metrics(request):
    return json(None, status=204)


if __name__ == '__main__':
    app.run()
