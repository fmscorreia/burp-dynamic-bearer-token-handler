from burp import IBurpExtender, ISessionHandlingAction
import json

JSON_TOKEN_KEY          = 'access_token'
AUTH_HEADER             = 'Authorization: '
AUTH_VALUE_PREFIX       = 'Bearer '
AUTH_VALUE_DUMMY        = 'DUMMY'
AUTH_FAILED             = 'Authentication macro returned status code '
NO_AUTH_MACRO_FOUND     = 'Authentication macro not found. Check Session Handling Rule configuration.'
COULD_NOT_DESERIALIZE   = 'Could not deserialize JSON from Authentication macro response'


#
# "Static" utility class
#
class Callbacks():

    callbacks       = None
    bearer_token    = None

    def __init__(self, callbacks):
        Callbacks.callbacks = callbacks
        Callbacks.helpers   = callbacks.getHelpers()

    # add / update authorization header in currentRequest
    @staticmethod
    def set_authorization_header(currentRequest):
        request_info    = Callbacks.helpers.analyzeRequest(currentRequest)
        request_headers = request_info.getHeaders()

        # remove Authorization header, if found in request_headers list
        for i, header in enumerate(request_headers):
            if header.startswith(AUTH_HEADER + AUTH_VALUE_PREFIX):
                request_headers.remove(i)
                break

        # on first request, no bearer token will yet be cached. set header to dummy value.
        # request will fail and trigger the authentication macro
        if Callbacks.bearer_token is None:
            auth_header_value   = AUTH_VALUE_DUMMY
        else:
            auth_header_value   = Callbacks.bearer_token[JSON_TOKEN_KEY]

        # insert Authorization header at position 2 (right after Host header)
        request_headers.add(2, AUTH_HEADER + AUTH_VALUE_PREFIX + auth_header_value)

        # build new request
        request_body    = currentRequest.getRequest()[request_info.getBodyOffset():]
        message = Callbacks.helpers.buildHttpMessage(request_headers, request_body)
        currentRequest.setRequest(message)


#
# Implements ISessionHandlingAction.
# This session handling action should be invoked after an authentication macro, in the context of
# a 'Check session is valid' action. It deserializes the JSON object returned in the authentication
# macro response. After extracting the bearer token, it updates the current request
#
class ParseBearerTokenAction(ISessionHandlingAction):

    def __init__(self):
        Callbacks.callbacks.registerSessionHandlingAction(self)

    def getActionName(self):
        return "Parse Bearer Token"

    def performAction(self, currentRequest, macroItems):
        if macroItems is None:
            Callbacks.callbacks.issueAlert(NO_MACRO_FOUND)
        else:
            response        = macroItems[0].getResponse()
            response_info   = Callbacks.helpers.analyzeResponse(response)

            if response_info.getStatusCode() == 200:
                response_body   = Callbacks.helpers.bytesToString(
                        response[response_info.getBodyOffset():])

                # deserialize JSON object
                try:
                    Callbacks.bearer_token  = json.loads(response_body)
                    Callbacks.set_authorization_header(currentRequest)
                except JSONDecodeError:
                    Callbacks.callbacks.issueAlert(COULD_NOT_DESERIALIZE)

            else:
                Callbacks.callbacks.issueAlert(AUTH_FAILED + str(response_info.getStatusCode()))


#
# Implements ISessionHandlingAction.
# Sets the Authorization header for the current request with the cached bearer token.
# This should be set as the first action of the Session Handling Rule
#
class SetAuthorizationHeaderAction(ISessionHandlingAction):

    def __init__(self):
        Callbacks.callbacks.registerSessionHandlingAction(self)

    def getActionName(self):
        return "Set Authorization Header"

    def performAction(self, currentRequest, macroItems):
        Callbacks.set_authorization_header(currentRequest)


#
# Implements IBurpExtender.
#
class BurpExtender(IBurpExtender):

    _extension_name = 'Dynamic Bearer Token Handler'

    def registerExtenderCallbacks(self, callbacks):
        Callbacks(callbacks)
        Callbacks.callbacks.setExtensionName(self._extension_name)
        Callbacks.callbacks.printOutput(self._extension_name + " extension loaded")

        # register session handling actions
        ParseBearerTokenAction()
        SetAuthorizationHeaderAction()
