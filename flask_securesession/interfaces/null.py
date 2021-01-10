# coding: utf-8

from .base import SessionInterface


class NullSessionInterface(SessionInterface):
    """Used to open a :class:`flask.sessions.NullSession` instance.
    """

    def open_session(self, app, request):
        return None
