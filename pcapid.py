import secrets
import string

from passlib.context import CryptContext
from sanic import Sanic
from sanic.exceptions import abort
from sanic.request import json_loads
from sanic.response import file, json, json_dumps
from tortoise import fields
from tortoise.contrib.sanic import register_tortoise
from tortoise.exceptions import DoesNotExist
from tortoise.models import Model
from tortoise.transactions import in_transaction


class User(Model):
    id = fields.IntField(pk=True, generated=True)
    name = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255, unique=True)
    password_hash = fields.CharField(max_length=255)
    warp = fields.BooleanField(default=False)
    staff = fields.BooleanField(default=False)
    team_id = fields.CharField(max_length=255, default='')

class Host(Model):
    id = fields.CharField(max_length=255, pk=True)
    name = fields.CharField(max_length=255, null=True)
    session_id = fields.CharField(max_length=255, unique=True)
    user = fields.ForeignKeyField('models.User', related_name='hosts')

class Peer(object):
    def __init__(self):
        self.infos = False
        self.connected = False

class PermissionDenied(Exception):
    pass


peers = {}
app = Sanic(__name__)
pwd_context = CryptContext(schemes=['argon2'], deprecated='auto')


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

    unsanitized_session_id = request.args['session_id'][0]

    try:
        host = await Host.get(session_id=unsanitized_session_id)
    except DoesNotExist:
        abort(401)

    peer_id = host.id
    peer = peers[peer_id]
    peer.build = request.args['build'][0] or None
    peer.sdk_version = request.args['sdk_version'][0] or None
    peer.ws = ws

    if peer.infos:
        peer.connected = True

    try:
        while True:
            try:
                data = await ws.recv()
                await handle_data(peer_id, peer, json_loads(data))
            except PermissionDenied:
                pass
    finally:
        peer.connected = False
        peer.ws = None


async def check_permissions(from_peer_id, to_peer_id):
    from_host = await Host.get(id=from_peer_id).prefetch_related('user__hosts')
    own_host = await from_host.user.hosts.filter(id=to_peer_id).exists()
    if own_host:
        print('Permission from %s to %s allowed' % (from_peer_id, to_peer_id))
        return

    print('Permission from %s to %s denied' % (from_peer_id, to_peer_id))
    raise PermissionDenied()


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

        host = await Host.get(id=peer_id).update(name=peer.name)

    elif action == 'offer':
        to_peer_id = data['payload']['to']
        await check_permissions(peer_id, to_peer_id)

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
        await send_message(to_peer_id, build_message('offer_relay', payload))

    elif action == 'answer':
        to_peer_id = data['payload']['to']
        await check_permissions(peer_id, to_peer_id)

        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(to_peer_id, build_message('answer_relay', payload))

    elif action == 'candex':
        to_peer_id = data['payload']['to']
        await check_permissions(peer_id, to_peer_id)

        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(to_peer_id, build_message('candex_relay', payload))

    elif action == 'offer_cancel':
        to_peer_id = data['payload']['to']
        await check_permissions(peer_id, to_peer_id)

        payload = data['payload'].copy()
        payload.update({
            'from': peer_id,
        })
        await send_message(to_peer_id, build_message('offer_cancel_relay', payload))

    elif action == 'client_disconnect':
        peer.connected = False

    else:
        print('Unknown action: %s' % data.action)


@app.route('/source')
async def source(request):
    return await file(__file__)


@app.route('/me')
async def me(request):
    unsanitized_session_id = request.token
    try:
        host = await Host.get(session_id=unsanitized_session_id).prefetch_related('user')
    except DoesNotExist:
        abort(401)

    user = host.user

    user_data = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'warp': user.warp,
        'staff': user.staff,
        'team_id': user.team_id,
        'is_saml': False,
        'app_config': {},
    }
    return json({'data': user_data})


@app.route('/v1/auth', methods=['POST'])
async def auth(request):
    if 'email' not in request.json:
        return json({'error': 'Must supply email.'}, status=403)
    if 'password' not in request.json:
        return json({'error': 'Must supply password.'}, status=403)
    if len(request.json['password']) < 8:
        return json({'error': 'Password too short.'}, status=403)

    unsanitized_email = request.json['email']
    unsanitized_password = request.json['password']

    async with in_transaction() as connection:
        user = await User.get_or_none(email=unsanitized_email).using_db(connection)
        if user is None:
            user = await User.create(name=unsanitized_email, email=unsanitized_email, password_hash=pwd_context.hash(unsanitized_password), using_db=connection)
        else:
            if not pwd_context.verify(unsanitized_password, user.password_hash):
                return json({'error': 'Your email/password combination is incorrect.'}, status=403)

    session_id = secrets.token_hex(32)
    try:
        if 'host_peer_id' not in request.json:
            raise DoesNotExist()

        unsanitized_peer_id = request.json['host_peer_id']
        if await user.hosts.all().get(id=unsanitized_peer_id).update(session_id=session_id) != 1:
            raise DoesNotExist()

        peer_id = unsanitized_peer_id
    except DoesNotExist:
        peer_id = rand_string(28)
        host = await Host.create(id=peer_id, session_id=session_id, user=user)

    peers[peer_id] = Peer()
    data = {
        'instance_id': '',
        'user_id': user.id,
        'session_id': session_id,
        'host_peer_id': peer_id,
    }
    return json(data, status=201)


@app.route('/v2/hosts')
async def hosts(request):
    unsanitized_session_id = request.token
    try:
        my_host = await Host.get(session_id=unsanitized_session_id).prefetch_related('user__hosts__user')
    except DoesNotExist:
        abort(401)

    my_peer_id = my_host.id

    hosts = []
    for remote_host in my_host.user.hosts:
        remote_peer_id = remote_host.id
        if remote_peer_id not in peers:
            continue

        remote_peer = peers[remote_peer_id]

        if not remote_peer.connected:
            continue

        remote_user = remote_host.user
        hosts.append({
            'user': {
                'id': remote_user.id,
                'name': remote_user.name,
                'warp': remote_user.warp,
                'team_id': remote_user.team_id,
                'external_id': '',
                'external_provider': '',
            },
            'peer_id': remote_peer_id,
            'game_id': remote_peer.game_id,
            'build': remote_peer.build,
            'description': remote_peer.desc,
            'max_players': remote_peer.max_players,
            'mode': remote_peer.mode,
            'name': remote_peer.name,
            'players': remote_peer.players,
            'public': remote_peer.public,
            'self': remote_peer_id == my_peer_id,
        })

    data = {
        'data': hosts,
        'has_more': False,
    }
    return json(data)


@app.route('/friend-requests')
async def friend_requests(request):
    unsanitized_session_id = request.token
    try:
        host = await Host.get(session_id=unsanitized_session_id)
    except DoesNotExist:
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


register_tortoise(app, db_url='sqlite://:memory:', modules={'models': [__name__]}, generate_schemas=True)


if __name__ == '__main__':
    app.run()
