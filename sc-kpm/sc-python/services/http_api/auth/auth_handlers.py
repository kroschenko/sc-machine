import json
import jwt
import time
import OpenSSL.crypto as crypto
from os.path import isfile

from http_api.auth import constants as cnt
from http_api.auth.base_handler import BaseHandler
from http_api.auth.common import get_response_message
from http_api.auth.config import params
from http_api.auth.database import DataBase
from http_api.auth.validators import TokenValidator, TokenType


def _generate_token(token_type: TokenType) -> bytes:
    if not isfile(params[cnt.PRIVATE_KEY_PATH]):
        _generate_keys()
    with open(params[cnt.PRIVATE_KEY_PATH], 'rb') as file:
        private_key = file.read()
    access_token_life_span = params[cnt.ACCESS_TOKEN_LIFE_SPAN]
    refresh_token_life_span = params[cnt.REFRESH_TOKEN_LIFE_SPAN]
    life_span = access_token_life_span if token_type == TokenType.ACCESS else refresh_token_life_span
    payload = {
        cnt.ISS: params[cnt.ISSUER],
        cnt.EXP: time.time() + life_span,
    }
    token = jwt.encode(payload, key=private_key, algorithm='RS256')
    return token


def _generate_keys() -> None:
    pkey = crypto.PKey()
    pkey.generate_key(type=crypto.TYPE_RSA, bits=2048)
    with open(params[cnt.PRIVATE_KEY_PATH], "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    with open(params[cnt.PUBLIC_KEY_PATH], "wb") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, pkey))


class TokensHandler(BaseHandler):
    def post(self) -> None:
        database = DataBase()
        username, password = self._get_user_credentials()
        if database.is_user_valid(username, password):
            access_token_data = _generate_token(TokenType.ACCESS)
            refresh_token_data = _generate_token(TokenType.REFRESH)
            response = json.dumps({
                cnt.MSG_CODE: params[cnt.MSG_CODES][cnt.MSG_ALL_DONE],
                cnt.ACCESS_TOKEN: {
                    cnt.TOKEN: access_token_data.decode(),
                    cnt.TOKEN_TYPE: cnt.JWT,
                    cnt.EXPIRES_IN: params[cnt.ACCESS_TOKEN_LIFE_SPAN],
                },
                cnt.REFRESH_TOKEN: {
                    cnt.TOKEN: refresh_token_data.decode(),
                    cnt.TOKEN_TYPE: cnt.JWT,
                    cnt.EXPIRES_IN: params[cnt.REFRESH_TOKEN_LIFE_SPAN],
                }
            })
        else:
            response = get_response_message(params[cnt.MSG_CODES][cnt.MSG_USER_NOT_FOUND])
        self.write(response)

    def _get_user_credentials(self):
        data = json.loads(self.request.body)
        name = data[cnt.NAME] if cnt.NAME in data else False
        password = data[cnt.PASSWORD] if cnt.PASSWORD in data else False
        return name, password


class AccessTokenHandler(BaseHandler):
    @TokenValidator.validate_typed_token(TokenType.REFRESH)
    def post(self) -> None:
        access_token_data = _generate_token(TokenType.ACCESS)
        response = json.dumps({
            cnt.MSG_CODE: params[cnt.MSG_CODES][cnt.MSG_ALL_DONE],
            cnt.TOKEN: access_token_data.decode(),
            cnt.TOKEN_TYPE: cnt.JWT,
            cnt.EXPIRES_IN: params[cnt.ACCESS_TOKEN_LIFE_SPAN],
        })
        self.write(response)
