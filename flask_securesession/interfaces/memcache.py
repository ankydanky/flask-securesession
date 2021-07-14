# coding: utf-8

import time

from .base import SessionInterface
from ..sessions import MemcachedSession
from ..helpers import encrypt, decrypt, total_seconds

import pickle

from itsdangerous import BadSignature, want_bytes


class MemcachedSessionInterface(SessionInterface):
    """A Session interface that uses memcached as backend.

    .. versionadded:: 0.2
        The `use_signer` parameter was added.

    :param client: A ``memcache.Client`` instance.
    :param key_prefix: A prefix that is added to all Memcached store keys.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    serializer = pickle
    session_class = MemcachedSession

    def __init__(self, client, key_prefix, use_signer=True, permanent=True):
        if client is None:
            client = self._get_preferred_memcache_client()
            if client is None:
                raise RuntimeError('no memcache module found')
        self.client = client
        self.key_prefix = key_prefix
        self.use_signer = use_signer
        self.permanent = permanent
        self.has_same_site_capability = hasattr(self, "get_cookie_samesite")

    def _get_preferred_memcache_client(self):
        servers = ['127.0.0.1:11211']
        try:
            import pylibmc
        except ImportError:
            pass
        else:
            return pylibmc.Client(servers)

        try:
            import memcache
        except ImportError:
            pass
        else:
            return memcache.Client(servers)

    def _get_memcache_timeout(self, timeout):
        """
        Memcached deals with long (> 30 days) timeouts in a special
        way. Call this function to obtain a safe value for your timeout.
        """
        if timeout > 2592000:  # 60*60*24*30, 30 days
            # See http://code.google.com/p/memcached/wiki/FAQ
            # "You can set expire times up to 30 days in the future. After that
            # memcached interprets it as a date, and will expire the item after
            # said date. This is a simple (but obscure) mechanic."
            #
            # This means that we have to switch to absolute timestamps.
            timeout += int(time.time())
        return timeout

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

        full_session_key = self.key_prefix + sid
        if PY2 and isinstance(full_session_key, unicode):
            full_session_key = full_session_key.encode('utf-8')
        val = self.client.get(full_session_key)
        if val is not None:
            val = decrypt(app.secret_key, val)
            try:
                if not PY2:
                    val = want_bytes(val)
                data = self.serializer.loads(val)
                return self.session_class(data, sid=sid)
            except Exception as e:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        full_session_key = self.key_prefix + session.sid
        if PY2 and isinstance(full_session_key, unicode):
            full_session_key = full_session_key.encode('utf-8')
        if not session:
            if session.modified:
                self.client.delete(full_session_key)
                response.delete_cookie(app.session_cookie_name, domain=domain, path=path)
            return
        
        conditional_cookie_kwargs = {}
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        if self.has_same_site_capability:
            conditional_cookie_kwargs["samesite"] = self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)
        if not PY2:
            val = self.serializer.dumps(dict(session), 0)
        else:
            val = self.serializer.dumps(dict(session))
        val = encrypt(app.secret_key, val)
        self.client.set(
            full_session_key,
            val,
            self._get_memcache_timeout(total_seconds(app.permanent_session_lifetime))
        )
        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session.sid))
        else:
            session_id = session.sid
        response.set_cookie(app.session_cookie_name, session_id,
                            expires=expires, httponly=httponly,
                            domain=domain, path=path, secure=secure,
                            **conditional_cookie_kwargs)
