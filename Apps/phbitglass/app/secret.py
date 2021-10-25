# File: app/secret.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

class Secret(object):
    """ For the sake of 'extra' security echo a dummy string back from the server.
        The dummy value of the same length will pass the form validation so there is no need to retype.
        On the way back to the server, detect it and don't override the value keeping it the same.
        Furthermore, explicitly clear the value when the session goes out.
    """

    def __get__(self, instance, owner):
        return '' if instance.pswd is None or instance.pswd == '' else '*' * len(instance.pswd)

    def __set__(self, instance, value):
        pswd = value if instance.pswd is None or instance.pswd == '' or value != (
            '*' * len(instance.pswd)) else instance.pswd
        if pswd != instance.pswd:
            instance.pswd = pswd
            if instance.pswd != '':
                instance.save()


class Password(object):
    secret = Secret()

    def __init__(self, name, user='secret'):
        self.pswd = None
        self.name = name
        self.user = user

    def simpleHash(self, s):
        import ctypes
        v = ord(s[0]) << 7
        for c in s:
            v = ctypes.c_int32((int(1000003) * v) & 0xffffffff).value ^ ord(c)
        v = v ^ len(s)
        if v == -1:
            v = -2
        return int(v)

    # TODO Call this when session dies, will need to reload in every new session
    def clear(self):
        self.pswd = None

    def load(self):
        """ Load from the secure storage
        """
        try:
            from qpylib.encdec import Encryption
            self.pswd = Encryption({'name': self.name, 'user': self.simpleHash(self.user)}).decrypt()
        except Exception as ex:
            pass

    def save(self):
        """ Save to the secure storage
        """
        try:
            from qpylib.encdec import Encryption
            Encryption({'name': self.name, 'user': self.simpleHash(self.user)}).encrypt(self.pswd)
        except Exception as ex:
            pass
