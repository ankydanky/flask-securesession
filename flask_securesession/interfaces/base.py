# coding: utf-8

from uuid import uuid4

from flask.sessions import SessionInterface as FlaskSessionInterface

from itsdangerous import Signer


class SessionInterface(FlaskSessionInterface):
    
    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app):
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt='flask-session', key_derivation='hmac')
