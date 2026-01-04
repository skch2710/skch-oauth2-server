DROP TABLE IF EXISTS oauth2_authorization;

CREATE TABLE oauth2_authorization (
    id varchar(100) PRIMARY KEY,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000),
    attributes text,
    state varchar(500),
    authorization_code_value text,
    authorization_code_issued_at timestamp,
    authorization_code_expires_at timestamp,
    authorization_code_metadata text,
    access_token_value text,
    access_token_issued_at timestamp,
    access_token_expires_at timestamp,
    access_token_metadata text,
    access_token_type varchar(100),
    access_token_scopes varchar(1000),
    oidc_id_token_value text,
    oidc_id_token_issued_at timestamp,
    oidc_id_token_expires_at timestamp,
    oidc_id_token_metadata text,
    refresh_token_value text,
    refresh_token_issued_at timestamp,
    refresh_token_expires_at timestamp,
    refresh_token_metadata text,
    user_code_value text,
    user_code_issued_at timestamp,
    user_code_expires_at timestamp,
    user_code_metadata text,
    device_code_value text,
    device_code_issued_at timestamp,
    device_code_expires_at timestamp,
    device_code_metadata text
);


DROP TABLE IF EXISTS oauth2_registered_client;

CREATE TABLE oauth2_registered_client (
    id varchar(100) PRIMARY KEY,

    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,

    client_secret varchar(200),
    client_secret_expires_at timestamp,

    client_name varchar(200) NOT NULL,

    -- Serialized as comma-separated values
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,

    redirect_uris varchar(1000),
    post_logout_redirect_uris varchar(1000),

    scopes varchar(1000) NOT NULL,

    -- JSON (String serialization)
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL
);


INSERT INTO oauth2_registered_client (
    id,
    client_id,
    client_id_issued_at,
    client_secret,
    client_secret_expires_at,
    client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris,
    post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    uuid_generate_v4()::varchar,
    'skch_ch',
    TIMESTAMP '2026-01-01 16:44:22.40673',
    '$2a$10$EfWgodzdjuQctsah.8hSVekfcbzo.HRwvY.7RQwnKfSATXnXIGrn.',
    NULL,
    'Internal OAuth Client',
    'client_secret_basic',
    'refresh_token,custom_pwd,client_credentials,authorization_code',
    'http://127.0.0.1:8080/login/oauth2',
    'http://127.0.0.1:8080/',
    'read,openid,profile,write',
    '{
      "@class":"java.util.Collections$UnmodifiableMap",
      "settings.client.require-proof-key":true,
      "settings.client.require-authorization-consent":false
    }',
    '{
      "@class":"java.util.Collections$UnmodifiableMap",
      "settings.token.reuse-refresh-tokens":false,
      "settings.token.x509-certificate-bound-access-tokens":false,
      "settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],
      "settings.token.access-token-time-to-live":["java.time.Duration",900.000000000],
      "settings.token.access-token-format":{
        "@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat",
        "value":"self-contained"
      },
      "settings.token.refresh-token-time-to-live":["java.time.Duration",21600.000000000],
      "settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],
      "settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]
    }'
);

INSERT INTO oauth2_registered_client (
    id,
    client_id,
    client_id_issued_at,
    client_secret,
    client_secret_expires_at,
    client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris,
    post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    uuid_generate_v4()::varchar,
    'auth_code_client',
    NOW(),
    NULL,
    NULL,
    'React BFF Client',
    'none', 
    'authorization_code,refresh_token',
    'http://localhost:8060/auth/callback',
    NULL,
    'read,openid,profile',
    '{
      "@class":"java.util.Collections$UnmodifiableMap",
      "settings.client.require-proof-key":true,
      "settings.client.require-authorization-consent":false
    }',
    '{
      "@class":"java.util.Collections$UnmodifiableMap",
      "settings.token.reuse-refresh-tokens":false,
      "settings.token.access-token-time-to-live":["java.time.Duration",900.000000000],
      "settings.token.refresh-token-time-to-live":["java.time.Duration",604800.000000000],
      "settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]
    }'
);

DELETE FROM public.oauth2_authorization
WHERE (access_token_expires_at IS NOT NULL AND access_token_expires_at < NOW())
OR (authorization_code_expires_at IS NOT NULL AND authorization_code_expires_at < NOW());


