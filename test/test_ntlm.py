import unittest
import mock
import requests
import responses
from requests_ntlm2 import HttpNtlm2Auth, InvalidCredentialsError, NtlmAuthenticationError


class RequestsNtlm2(unittest.TestCase):
    # [MS-NTHT] - v20151016

    @classmethod
    def setUpClass(cls):
        cls.url = "http://www.test.com"
        cls.domain = 'asgard'
        cls.username = 'odin'
        cls.password = 'yggdrasill'
        cls.body = 'body-content'
        cls.context = 'requests_ntlm2.requests_ntlm2.NtlmContext.initialize_security_context'

    def test_no_authentication_required(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r:
            r.add("GET", self.url, self.body, status=200)
            response = requests.get(url=self.url, auth=authentication)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.body)

    def test_only_ntlm_is_accpeted(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers=self.ntlm.empty, status=401)
            r.add("GET", self.url, adding_headers=self.ntlm.challenge, headers=self.ntlm.negotiate, status=401)
            r.add("GET", self.url, self.body, headers=self.ntlm.authenticate, status=200)

            response = requests.get(url=self.url, auth=authentication)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.body)

    def test_only_negotiate_is_accepeted(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers=self.nego.empty, status=401)
            r.add("GET", self.url, adding_headers=self.nego.challenge, headers=self.nego.negotiate, status=401)
            r.add("GET", self.url, self.body, headers=self.nego.authenticate, status=200)

            response = requests.get(url=self.url, auth=authentication)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.body)

    def test_ntlm_is_preferred_to_negotiate(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers={'www-authenticate': 'Negotiate, NTLM'}, status=401)
            r.add("GET", self.url, adding_headers=self.ntlm.challenge, headers=self.ntlm.negotiate, status=401)
            r.add("GET", self.url, self.body, headers=self.ntlm.authenticate, status=200)

            response = requests.get(url=self.url, auth=authentication)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.body)

    def test_neither_ntlm_or_negotiate_are_accepted(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers={'www-authenticate': 'Kerberos'}, status=401)

            self.assertRaises(NtlmAuthenticationError, requests.get, url=self.url, auth=authentication)

    def test_rejected_ntlm_token(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers=self.ntlm.empty, status=401)
            r.add("GET", self.url, adding_headers=self.ntlm.empty, status=401)

            self.assertRaises(NtlmAuthenticationError, requests.get, url=self.url, auth=authentication)

    def test_rejected_negotiate_token(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers=self.nego.empty, status=401)
            r.add("GET", self.url, adding_headers=self.nego.empty, status=401)

            self.assertRaises(NtlmAuthenticationError, requests.get, url=self.url, auth=authentication)

    def test_rejected_ntlm_authenticate_token(self):
        authentication = HttpNtlm2Auth(self.domain, self.username, self.password)
        with responses.RequestsMock(assert_all_requests_are_fired=True) as r, mock.patch(self.context) as c:
            c.return_value = self.mock_security_context()

            r.add("GET", self.url, adding_headers=self.ntlm.empty, status=401)
            r.add("GET", self.url, adding_headers=self.ntlm.challenge, headers=self.ntlm.negotiate, status=401)
            r.add("GET", self.url, adding_headers=self.ntlm.empty, headers=self.ntlm.authenticate, status=401)

            self.assertRaises(InvalidCredentialsError, requests.get, url=self.url, auth=authentication)

    # TODO: handle invalid challenge token
    def test_invalid_ntlm_challenge(self):
        pass

    # TODO: test the body is withheld until the last response
    def test_body_is_not_sent_until_final_response(self):
        pass

    # TODO: ensure reusing the auth handler works
    def test_context_is_reset_between_requests(self):
        pass

    def mock_security_context(self):
        yield self.tokens.negotiate
        yield self.tokens.authenticate

    #
    class ContextTokens(object):
        negotiate = 'negotiate'
        authenticate = 'authenticate'

    class NtlmHeaders(object):
        empty = {'www-authenticate': 'NTLM'}
        challenge = {'www-authenticate': 'NTLM Y2hhbGxlbmdl'}
        negotiate = {'Authorization': 'NTLM bmVnb3RpYXRl'}
        authenticate = {'Authorization': 'NTLM YXV0aGVudGljYXRl'}

    #
    class NegotiateHeaders(object):
        empty = {'www-authenticate': 'Negotiate'}
        challenge = {'www-authenticate': 'Negotiate Y2hhbGxlbmdl'}
        negotiate = {'Authorization': 'Negotiate bmVnb3RpYXRl'}
        authenticate = {'Authorization': 'Negotiate YXV0aGVudGljYXRl'}

    ntlm = NtlmHeaders()
    nego = NegotiateHeaders()
    tokens = ContextTokens()

if __name__ == '__main__':
    unittest.main()