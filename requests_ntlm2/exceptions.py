from requests.exceptions import RequestException


class NtlmAuthenticationError(RequestException):
    """NTLM Error"""

class InvalidCredentialsError(NtlmAuthenticationError):
    """Invalid Username or Password"""
