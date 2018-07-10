This is a docker container for testing SAML2 IdP provider with POST binding.

Workflow:

1. Build waldur-saml2-idp Docker image using make command in current directory.
2. Modify Waldur settings using config/saml_settings.py file.
3. Start Waldur MasterMind server using waldur runserver 127.0.0.1:8080 command.
4. Start SAML2 IdP server using Docker on 9080 port.
5. Start Waldur HomePort server on 8001 port.
6. Login using user1:user1pass credentials.

```bash
docker run \
    --name=testsamlidp_idp \
    -p 9080:8080 \
    -p 9443:8443 \
    -e SIMPLESAMLPHP_SP_ENTITY_ID=http://127.0.0.1:8080/api-auth/saml2/metadata/ \
    -e SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE=http://127.0.0.1:8080/api-auth/saml2/login/complete/ \
    -e SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE=http://127.0.0.1:8080/api-auth/saml2/logout/complete/ \
    -d waldur-saml2-idp
```
