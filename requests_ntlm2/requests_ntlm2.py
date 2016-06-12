# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# requests-ntlm2 is licensed under the Apache License, Version 2.0 (the "License");
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

# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
# licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
import base64
from requests.auth import AuthBase
from ntlmlib.context import NtlmContext
from ntlmlib.authentication import PasswordAuthentication

from .exceptions import InvalidCredentialsError, NtlmAuthenticationError


class HttpNtlm2Auth(AuthBase):
    def __init__(self, domain, username, password):
        self.body = ''
        self.context = None
        self.password_authenticator = PasswordAuthentication(domain, username, password)

    @staticmethod
    def _get_ntlm_header(response, scheme):
        headers = response.headers.get('www-authenticate', '')
        padded_scheme = scheme + ' '
        encoded_token = [
            t.strip()[len(padded_scheme):] for t in (h.strip() for h in headers.split(','))
            if t.startswith(padded_scheme)
        ]
        if encoded_token:
            return base64.b64decode(encoded_token[0])
        return None

    @staticmethod
    def _set_ntlm_response(request, scheme, token, body=''):
        request.body = body
        request.headers['Content-Length'] = str(len(body))
        request.headers['Authorization'] = '{0} {1}'.format(scheme, base64.b64encode(token).decode('ascii'))
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
                raise NtlmAuthenticationError("The remote server rejected NTLM negotiation")

            token = context_generator.send(challenge_response)
            http_response = yield self._set_ntlm_response(http_response.request, scheme, token, self.body)

            if http_response.status_code == 401:
                raise InvalidCredentialsError("The remote server rejected the supplied username or password")

    def handle_401(self, response, **kwargs):
        attempt_schemes = ['NTLM', 'Negotiate']
        authenticate_header = response.headers.get('www-authenticate', '')
        supported_schemes = [scheme for scheme in attempt_schemes if scheme in authenticate_header]
        if supported_schemes:
            context = NtlmContext(self.password_authenticator, session_security='none')
            ntlm_processor = self._ntlm_processor(context, supported_schemes[0])
            next(ntlm_processor)

            while response.status_code == 401:
                # This is required
                response.content
                response.raw.release_conn()
                client_request = ntlm_processor.send(response)
                response = response.connection.send(client_request, **kwargs)
        else:
            raise NtlmAuthenticationError("The remote server does not support NTLM authentication")

        return response

    def handle_response(self, response, **kwargs):
        if response.status_code == 401:
            response = self.handle_401(response, **kwargs)
        return response

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook('response', self.handle_response)

        # We should not send any body content to the target host until we have established a security context through
        # the 'handle_response' hook, we'll store the body and send it with the final response.
        if self.context is None and request.body:
            self.body = str(request.body)
            request.body = ''

        return request
