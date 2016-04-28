SAML2-based backend
^^^^^^^^^^^^^^^^^^^

Endpoint URL: ``/api-auth/saml2/``

Valid request example:

.. code-block:: http

    POST /api-auth/saml2/ HTTP/1.1
    Accept: application/json
    Content-Type: application/json
    Host: example.com

    {
        "saml2response": "SAML_PAYLOAD",
    }

Success response example:

.. code-block:: http

    HTTP/1.0 200 OK
    Allow: POST, OPTIONS
    Content-Type: application/json
    Vary: Accept, Cookie

    {
        "token": "c84d653b9ec92c6cbac41c706593e66f567a7fa4"
    }

Invalid token can result in a failure like in the example below. In this case please enable/check concrete
problem in SAML2 log file.

.. code-block:: http

    HTTP/1.0 401 UNAUTHORIZED
    Allow: POST, OPTIONS
    Content-Type: application/json

    {
        "saml2response": ["SAML2 response has errors."]
    }

