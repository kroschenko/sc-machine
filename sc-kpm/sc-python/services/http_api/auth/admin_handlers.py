import asyncio
from asyncio.tasks import wait
import json

import websockets
from tornado import websocket

from http_api.auth import constants as cnt
from http_api.auth.base_handler import BaseHandler
from http_api.auth.common import get_response_message
from http_api.auth.database import DataBase
from http_api.auth.validators import TokenValidator, TokenType
from http_api.auth.verifiers import username_verifier
from sc import *

def _verify_user_info_in_database(database: DataBase, name: str, password: str) -> str:
    if not username_verifier.verify(name):
        message_desc = cnt.MSG_INVALID_USERNAME
    elif len(password.strip()) == 0:
        message_desc = cnt.MSG_INVALID_PASSWORD
    elif database.is_such_user_in_base(name):
        message_desc = cnt.MSG_USER_IS_IN_BASE
    else:
        message_desc = cnt.MSG_ALL_DONE
    return message_desc

def _check_if_user_in_base(database: DataBase, name: str) -> str:
    if not database.is_such_user_in_base(name):
        message_desc = cnt.MSG_USER_NOT_FOUND
    else:
        message_desc = cnt.MSG_ALL_DONE
    return message_desc


async def _check_if_user_in_kb(username: str):
    async with websockets.connect('ws://localhost:8090/ws_json') as ws:
        payload = [
                {
                    "command": "find",
                    "data": username
                }
                ]
        get_login_links = {"id": 1, "type": "content", "payload": payload}
        await ws.send(json.dumps(get_login_links))
        response = await ws.recv()
        print(response)
        links = json.loads(response)['payload']
        print(links)
        if links == [[]]:
                print("No such user in kb")

        for link in links[0]:
            templ = _get_kb_user_template(link)
            
            print(templ)
            payload = {
                        "templ": templ
                      }
            print(payload)
            template_search = {"id": 2, "type": "search_template", "payload": templ}
            await ws.send(json.dumps(template_search))
            response = json.loads(await ws.recv())['payload']
            print(response)
            if response[0] == [[]]:
                print("No such user in kb")
            else:
                print("User found")


async def _get_kb_user_template(link):
    async with websockets.connect('ws://localhost:8090/ws_json') as ws:
        payload = [
                {
                    "command": "find",
                    "idtf": "nrel_login"
                },
                {
                    "command": "find",
                    "idtf": "ui_user"
                }
            ]
        resolve_ui_user = {"id": 1, "type": "keynodes", "payload": payload}
        await ws.send(json.dumps(resolve_ui_user))
        response = await ws.recv()
        login_addr, ui_user_addr = json.loads(response)["payload"]
        templ = []
        triple = []
        triple.append(
                {
                "type": "addr",
                "value": ui_user_addr
                })
        triple.append({
                "type": "type",
                "value": ScType.EdgeAccessVarPosPerm.ToInt(),
                 "alias": "_user_edge"
                })
        triple.append(
                {
                "type": "type",
                "value": ScType.NodeVar.ToInt(),
                "alias": "_user"
                })
        templ.append(triple)

        triple = []
        triple.append(
                {
                "type": "alias",
                "value": "_user"
                })
        triple.append(
                {
                "type": "type",
                "value": ScType.EdgeDCommonVar.ToInt(),
                "alias": "_link_edge"
                })
        triple.append(
                {
                "type": "addr",
                "value": link,
                "alias": "_link"
                })
        templ.append(triple)

        triple = []
        triple.append(
                {
                "type": "addr",
                "value": login_addr,
                })
        triple.append(
                {
                "type": "type",
                "value": ScType.EdgeAccessVarPosPerm.ToInt(),
                "alias": "_login_edge"
                })
        triple.append(
                {
                "type": "alias",
                "value": "_link_edge"
                })
        templ.append(triple)

        return templ


async def create_kb_user(username: str):
    async with websockets.connect('ws://localhost:8090/ws_json') as ws:
        await _check_if_user_in_kb(username)

        payload = [
                {
                    "command": "find",
                    "idtf": "nrel_login"
                },
                {
                    "command": "find",
                    "idtf": "ui_user"
                }
        ]
        resolve_ui_user = {"id": 1, "type": "keynodes", "payload": payload}
        await ws.send(json.dumps(resolve_ui_user))
        response = await ws.recv()
        login_addr, ui_user_addr = json.loads(response)["payload"]
        print(login_addr)
        print(ui_user_addr)
        payload = []
        payload.append({
            'el': 'link',
            'type': ScType.LinkConst.ToInt(),
            'content' : username
            })
        payload.append({
            'el': 'node',
            'type': ScType.NodeConst.ToInt()
            })
        payload.append({
            'el': 'edge',
            'src': {'type': 'ref', 'value': 1},
            'trg': {'type': 'ref', 'value': 0},
            'type': ScType.EdgeDCommonConst.ToInt()
            })
        payload.append({
            'el': 'edge',
            'src': {'type': 'addr', 'value': login_addr},
            'trg': {'type': 'ref', 'value': 2},
            'type': ScType.EdgeAccessConstPosPerm.ToInt()
            })
        payload.append({
            'el': 'edge',
            'src': {'type': 'addr', 'value': ui_user_addr},
            'trg': {'type': 'ref', 'value': 1},
            'type': ScType.EdgeAccessConstPosPerm.ToInt()
            })
        message = {"id": 2 ,"type": "create_elements", "payload": payload}
        print(message)
        await ws.send(json.dumps(message))
        print(await ws.recv())

async def delete_kb_user(username: str):
    async with websockets.connect('ws://localhost:8090/ws_json') as ws:
        payload = [
                {
                    "command": "find",
                    "data": username
                }
                ]
        get_login_links = {"id": 1, "type": "content", "payload": payload}
        await ws.send(json.dumps(get_login_links))
        response = await ws.recv()
        print(response)
        links = json.loads(response)['payload']

        for link in links[0]:
            templ = []

            templ = await _get_kb_user_template(link)

            print(templ)
            payload = {
                        "templ": templ
                      }
            print(payload)
            template_search = {"id": 2, "type": "search_template", "payload": templ}
            await ws.send(json.dumps(template_search))
            response = json.loads(await ws.recv())['payload']
            print(response)
            aliases = response['aliases']
            print(aliases.values())
            addrs = response['addrs']
            print(addrs[0])

            payload = []

            for value in aliases.values():
                print(addrs[0][value])
                payload.append(addrs[0][value])

            delete_elements = {"id": 3, "type": "delete_elements", "payload": payload}
            await ws.send(json.dumps(delete_elements))
            response = json.loads(await ws.recv())
            print(response)


async def update_kb_user(username: str, new_username: str):
    async with websockets.connect('ws://localhost:8090/ws_json') as ws:
        payload = [
                {
                    "command": "find",
                    "data": username
                }
                ]
        get_login_links = {"id": 1, "type": "content", "payload": payload}
        await ws.send(json.dumps(get_login_links))
        response = await ws.recv()
        print(response)
        links = json.loads(response)['payload']

        for link in links[0]:
            templ = await _get_kb_user_template(link)

            print(templ)
            payload = {
                        "templ": templ
                      }

            print(payload)
            template_search = {"id": 2, "type": "search_template", "payload": templ}
            await ws.send(json.dumps(template_search))
            response = json.loads(await ws.recv())['payload']
            print(response)
            aliases = response['aliases']
            print(aliases.values())
            addrs = response['addrs']
            print(addrs[0])

            link_addr = addrs[0][aliases['_link']]
            payload = [
                    {
                    "command": "set",
                    "addr": link_addr,
                    "type": "string",
                    "data": new_username
                    }
                    ]
            update_link = {"id": 3, "type": "content", "payload": payload}
            await ws.send(json.dumps(update_link))
            response = json.loads(await ws.recv())['payload']
            print(response)


class UserHandler(BaseHandler):
    @TokenValidator.validate_typed_token(TokenType.ACCESS)
    def post(self) -> None:
        """ Add new user """
        database = DataBase()
        request_params = self._get_request_params([cnt.NAME, cnt.PASSWORD])
        msg_desc = _verify_user_info_in_database(
            database,
            name=request_params[cnt.NAME],
            password=request_params[cnt.PASSWORD],
        )
        response = get_response_message(msg_desc)
        if msg_desc == cnt.MSG_ALL_DONE:
            database.add_user(**request_params)
            loop = asyncio.get_event_loop()
            loop.create_task(create_kb_user(request_params[cnt.NAME]))
        self.write(response)

    @TokenValidator.validate_typed_token(TokenType.ACCESS)
    def get(self) -> None:
        """ Get info about user """
        database = DataBase()
        request_params = self._get_request_params([cnt.NAME])
        human_info = database.get_user_by_name(**request_params)
        if human_info is not None:
            response = json.dumps({
                cnt.ID: human_info[cnt.ID],
                cnt.NAME: human_info[cnt.NAME]
            })
        else:
            response = get_response_message(cnt.MSG_USER_NOT_FOUND)
        self.write(response)

    @TokenValidator.validate_typed_token(TokenType.ACCESS)
    def delete(self) -> None:
        """ Delete user """
        database = DataBase()
        request_params = self._get_request_params([cnt.NAME])
        delete_users_count = database.delete_user_by_name(**request_params)
        if delete_users_count == 0:
            response = get_response_message(cnt.MSG_USER_NOT_FOUND)
        else:
            response = get_response_message(cnt.MSG_ALL_DONE)
            loop = asyncio.get_event_loop()
            loop.create_task(delete_kb_user(request_params[cnt.NAME]))
        self.write(response)

    @TokenValidator.validate_typed_token(TokenType.ACCESS)
    def put(self) -> None:
        """ Update user """
        database = DataBase()
        request_params = self._get_request_params([cnt.NAME, cnt.NEW_NAME, cnt.PASSWORD])
        msg_desc = _check_if_user_in_base(
                database,
                name=request_params[cnt.NAME])
        response = get_response_message(msg_desc)
        if msg_desc == cnt.MSG_ALL_DONE:
            msg_desc = _verify_user_info_in_database(
                database,
                name=request_params[cnt.NEW_NAME],
                password=request_params[cnt.PASSWORD]
            )
        response = get_response_message(msg_desc)
        if msg_desc == cnt.MSG_ALL_DONE:
            updates_users_count = database.update_user_by_name(**request_params)
            if updates_users_count == 0:
                response = get_response_message(cnt.MSG_USER_NOT_FOUND)
            else:
                loop = asyncio.get_event_loop()
                loop.create_task(update_kb_user(request_params[cnt.NAME], request_params[cnt.NEW_NAME]))
        self.write(response)


class UsersListHandler(BaseHandler):
    @TokenValidator.validate_typed_token(TokenType.ACCESS)
    def get(self) -> None:
        database = DataBase()
        users = database.get_users()
        response = json.dumps({
            cnt.USERS: users
        })
        self.write(response)
