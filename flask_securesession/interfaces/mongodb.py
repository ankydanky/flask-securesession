# coding: utf-8

import pickle

from datetime import datetime

from .base import SessionInterface
from ..sessions import MongoDBSession
from ..helpers import encrypt, decrypt, total_seconds

from itsdangerous import want_bytes


class MongoDBSessionInterface(SessionInterface):
    """A Session interface that uses mongodb as backend.

    .. versionadded:: 0.2
        The `use_signer` parameter was added.

    :param client: A ``pymongo.MongoClient`` instance.
    :param db: The database you want to use.
    :param collection: The collection you want to use.
    :param key_prefix: A prefix that is added to all MongoDB store keys.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    serializer = pickle
    session_class = MongoDBSession

    def __init__(self, client, db, collection, key_prefix, use_signer=True, permanent=True):
        if client is None:
            from pymongo import MongoClient
            client = MongoClient()
        self.client = client
        self.store = client[db][collection]
        self.key_prefix = key_prefix
        self.use_signer = use_signer
        self.permanent = permanent

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid=sid, permanent=self.permanent)
        if self.use_signer:
            signer = self._get_signer(app)
            if signer is None:
                return None
            try:
                sid_as_bytes = signer.unsign(sid)
                sid = sid_as_bytes.decode()
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid=sid, permanent=self.permanent)

        store_id = self.key_prefix + sid
        document = self.store.find_one({'id': store_id})
        if document and document.get('expiration') <= datetime.utcnow():
            # Delete expired session
            self.store.remove({'id': store_id})
            document = None
        if document is not None:
            try:
                val = document['val']
                data = self.serializer.loads(want_bytes(val))
                return self.session_class(data, sid=sid)
            except Exception as e:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        store_id = self.key_prefix + session.sid
        if not session:
            if session.modified:
                self.store.remove({'id': store_id})
                response.delete_cookie(app.session_cookie_name, domain=domain, path=path)
            return

        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))
        self.store.update(
            {'id': store_id},
            {
                'id': store_id,
                'val': val,
                'expiration': expires
            },
            True
        )
        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session.sid))
        else:
            session_id = session.sid
        response.set_cookie(
            app.session_cookie_name,
            session_id,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure
        )
