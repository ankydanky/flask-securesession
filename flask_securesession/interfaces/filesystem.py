# coding: utf-8

import os
import pickle

from .base import SessionInterface
from ..sessions import FileSystemSession
from ..helpers import encrypt, decrypt, total_seconds

from itsdangerous import want_bytes, BadSignature

from cachelib.file import FileSystemCache as FileSystemCacheBase


class FileSystemCache(FileSystemCacheBase):
    def __init__(self, cache_dir, threshold, mode):
        super().__init__(cache_dir, threshold=threshold, mode=mode)
    
    def get(self, key):
        """fix some EOFErrors if file got corrupt and remove file"""
        filename = self._get_filename(key)
        try:
            return super().get(key)
        except EOFError:
            os.remove(filename)
            return None
    
    def _remove_expired(self, now):
        """fix EOFErrors"""
        entries = self._list_dir()
        for fname in entries:
            try:
                with open(fname, "rb") as f:
                    expires = pickle.load(f)
                if expires != 0 and expires < now:
                    os.remove(fname)
                    self._update_count(delta=-1)
            except EOFError:
                os.remove(fname)
            except OSError:
                pass


class FileSystemSessionInterface(SessionInterface):
    """Uses the :class:`cachelib.file.FileSystemCache` as a session backend.

    .. versionadded:: 0.2
        The `use_signer` parameter was added.

    :param cache_dir: the directory where session files are stored.
    :param threshold: the maximum number of items the session stores before it starts deleting some.
    :param mode: the file mode wanted for the session files, default 0600
    :param key_prefix: A prefix that is added to FileSystemCache store keys.
    :param use_signer: Whether to sign the session id cookie or not.
    :param permanent: Whether to use permanent session or not.
    """

    session_class = FileSystemSession

    def __init__(
            self, cache_dir, threshold, mode, key_prefix,
            use_signer=True, permanent=True):
        self.cache = FileSystemCache(cache_dir, threshold=threshold, mode=mode)
        self.key_prefix = key_prefix
        self.use_signer = use_signer
        self.permanent = permanent
        self.has_same_site_capability = hasattr(self, "get_cookie_samesite")

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

        data = self.cache.get(self.key_prefix + sid)
        if data is not None:
            data = decrypt(app.secret_key, data)
            return self.session_class(data, sid=sid)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        if not session:
            if session.modified:
                self.cache.delete(self.key_prefix + session.sid)
                response.delete_cookie(app.session_cookie_name, domain=domain, path=path)
            return

        conditional_cookie_kwargs = {}
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        if self.has_same_site_capability:
            conditional_cookie_kwargs["samesite"] = self.get_cookie_samesite(app)
        expires = self.get_expiration_time(app, session)
        data = dict(session)
        data = encrypt(app.secret_key, data)
        self.cache.set(self.key_prefix + session.sid, data, total_seconds(app.permanent_session_lifetime))
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
            secure=secure,
            **conditional_cookie_kwargs
        )
