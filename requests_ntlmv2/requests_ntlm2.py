# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# requests-ntlmv2 is licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'ian.clegg@sourcewarp.com'


import base64

from requests.auth import AuthBase

from ntlmlib.context import NtlmContext
from ntlmlib.structure import Structure
from ntlmlib.authentication import PasswordAuthentication

class HttpNtlm2Auth(AuthBase):
    def __init__(self, domain, username, password):
        self.context = None
        self.password_authenticator = PasswordAuthentication(domain, username, password)

    @staticmethod
    def _get_ntlm_header(response, scheme):
        headers = response.headers.get('www-authenticate', '').lower()
        padded_scheme = scheme + ' '
        encoded_token = [
            t.strip()[len(padded_scheme):] for t in (h.strip() for h in headers.split(','))
            if t.startswith(padded_scheme)
        ]
        if encoded_token:
            return base64.b64decode(encoded_token[0])
        return None

    @staticmethod
    def _set_ntlm_response(request, scheme, token, body=None):
        request.headers['Authorization'] = '{0} {1}'.format(scheme, base64.b64encode(token))
        request.body = body
        return request

    def _ntlm_processor(self, context, scheme):
        response = (yield)
        header = self._get_ntlm_header(response, scheme)

        if header is None:
            context_generator = context.initialize_security_context()
            token = context_generator.send(None)
            http_response = yield self._set_ntlm_response(response.request, scheme, token)

            challenge_response = self._get_ntlm_header(http_response, scheme)
            if challenge_response is None:
                raise Exception("The remote server rejected NTLM negotiation")

            token = context_generator.send(challenge_response)
            http_response = yield self._set_ntlm_response(http_response.request, scheme, token, self.body)

            if self._get_ntlm_header(http_response, scheme) is None:
                raise Exception('The remote server rejected the supplied username or password')

    def handle_401(self, response, **kwargs):
        attempt_schemes = ['ntlm', 'negotiate']
        authenticate_header = response.headers.get('www-authenticate', '').lower()
        supported_schemes = [scheme for scheme in attempt_schemes if scheme in authenticate_header]
        if supported_schemes:
            self.context = NtlmContext(self.password_authenticator)
            ntlm_processor = self._ntlm_processor(self.context, supported_schemes[0])
            next(ntlm_processor)

            while response.status_code == 401:
                # This is required
                response.content
                response.raw.release_conn()
                client_request = ntlm_processor.send(response)
                response = response.connection.send(client_request, **kwargs)

        return response

    def handle_response(self, response, **kwargs):
        if response.status_code == 401:
            response = self.handle_401(response, **kwargs)

        # TODO check the response header to see if the response is encrypted first
        if response.status_code == 200:
            return response
        else:
            raise Exception("server did could decrypt our message? why")

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook('response', self.handle_response)

        # We should not send any body content to the target host until we have established a security context through
        # the 'handle_response' hook, we'll store the body until the final token
        if self.context is None:
            self.body = str(request.body)

        return request
