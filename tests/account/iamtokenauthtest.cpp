#include "iamtokenauth.h"

#include <QCryptographicHash>
#include <QUrlQuery>
#include <QtTest>

class IamTokenAuthTest : public QObject {
    Q_OBJECT

private slots:
    void createsClientCredentialsRequest()
    {
        const IamTokenAuthConfig config { QStringLiteral("https://iam.example/oauth2/token"),
                                          QStringLiteral("https://xmpp.example"), QStringLiteral("client id"),
                                          QStringLiteral("secret&value"), QStringLiteral("openid profile"), false };
        QNetworkRequest request;
        QByteArray      body;
        QString         error;

        QVERIFY(createIamTokenRequest(config, request, body, error));
        QCOMPARE(request.url(), QUrl(config.endpoint));
        QCOMPARE(request.header(QNetworkRequest::ContentTypeHeader).toString(),
                 QStringLiteral("application/x-www-form-urlencoded"));
        QCOMPARE(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
                 int(QNetworkRequest::ManualRedirectPolicy));

        const QUrlQuery form(QString::fromUtf8(body));
        QCOMPARE(form.queryItemValue(QStringLiteral("grant_type")), QStringLiteral("client_credentials"));
        QCOMPARE(form.queryItemValue(QStringLiteral("client_id")), config.clientId);
        QCOMPARE(form.queryItemValue(QStringLiteral("client_secret")), config.clientSecret);
        QCOMPARE(form.queryItemValue(QStringLiteral("audience")), config.audience);
        QCOMPARE(form.queryItemValue(QStringLiteral("scope")), config.scope);
    }

    void createsRefreshTokenRequest()
    {
        IamTokenAuthConfig config;
        config.endpoint = QStringLiteral("https://iam.example/oauth2/token");
        config.clientId = QStringLiteral("client-id");
        config.clientSecret = QStringLiteral("client-secret");
        config.audience = QStringLiteral("https://xmpp.example");
        config.scope = QStringLiteral("openid profile");

        QNetworkRequest request;
        QByteArray body;
        QString error;
        QVERIFY(createIamRefreshTokenRequest(config, QStringLiteral("refresh-token"), request, body, error));
        QCOMPARE(request.url(), QUrl(config.endpoint));
        QCOMPARE(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
                 int(QNetworkRequest::ManualRedirectPolicy));

        const QUrlQuery form(QString::fromUtf8(body));
        QCOMPARE(form.queryItemValue(QStringLiteral("grant_type")), QStringLiteral("refresh_token"));
        QCOMPARE(form.queryItemValue(QStringLiteral("refresh_token")), QStringLiteral("refresh-token"));
        QCOMPARE(form.queryItemValue(QStringLiteral("client_id")), config.clientId);
        QCOMPARE(form.queryItemValue(QStringLiteral("client_secret")), config.clientSecret);
        QCOMPARE(form.queryItemValue(QStringLiteral("audience")), config.audience);
        QCOMPARE(form.queryItemValue(QStringLiteral("scope")), config.scope);
    }

    void rejectsNonHttpsEndpoint()
    {
        IamTokenAuthConfig config;
        config.endpoint     = QStringLiteral("http://iam.example/token");
        config.clientId     = QStringLiteral("client");
        config.clientSecret = QStringLiteral("secret");
        QNetworkRequest request;
        QByteArray      body;
        QString         error;

        QVERIFY(!createIamTokenRequest(config, request, body, error));
        QVERIFY(!error.isEmpty());
    }

    void createsAuthorizationCodeRequestWithPkce()
    {
        IamTokenAuthConfig config;
        config.endpoint = QStringLiteral("https://iam.example/oauth2/token");
        config.authorizationEndpoint = QStringLiteral("https://iam.example/oauth2/authorize");
        config.redirectUri = QStringLiteral("psi-oauth://callback");
        config.audience = QStringLiteral("https://xmpp.example");
        config.clientId = QStringLiteral("client-id");
        config.scope = QStringLiteral("openid profile");

        const QString state = QStringLiteral("random-state");
        const QString verifier = QStringLiteral("random-code-verifier");
        QUrl authorizationUrl;
        QString error;
        QVERIFY(createIamAuthorizationRequest(config, state, verifier, authorizationUrl, error));

        const QUrlQuery query(authorizationUrl);
        QCOMPARE(query.queryItemValue(QStringLiteral("response_type")), QStringLiteral("code"));
        QCOMPARE(query.queryItemValue(QStringLiteral("client_id")), config.clientId);
        QCOMPARE(query.queryItemValue(QStringLiteral("redirect_uri")), config.redirectUri);
        QCOMPARE(query.queryItemValue(QStringLiteral("state")), state);
        QCOMPARE(query.queryItemValue(QStringLiteral("audience")), config.audience);
        QCOMPARE(query.queryItemValue(QStringLiteral("scope")), config.scope);
        const QByteArray expectedChallenge
            = QCryptographicHash::hash(verifier.toUtf8(), QCryptographicHash::Sha256)
                  .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        QCOMPARE(query.queryItemValue(QStringLiteral("code_challenge")).toLatin1(), expectedChallenge);
        QCOMPARE(query.queryItemValue(QStringLiteral("code_challenge_method")), QStringLiteral("S256"));
    }

    void createsAuthorizationCodeTokenRequest()
    {
        IamTokenAuthConfig config;
        config.endpoint = QStringLiteral("https://iam.example/oauth2/token");
        config.redirectUri = QStringLiteral("psi-oauth://callback");
        config.clientId = QStringLiteral("client-id");
        config.clientSecret = QStringLiteral("client-secret");
        config.audience = QStringLiteral("https://xmpp.example");

        QNetworkRequest request;
        QByteArray body;
        QString error;
        QVERIFY(createIamAuthorizationCodeTokenRequest(config, QStringLiteral("auth-code"),
                                                        QStringLiteral("pkce-verifier"), request, body, error));
        QCOMPARE(request.url(), QUrl(config.endpoint));
        QCOMPARE(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
                 int(QNetworkRequest::ManualRedirectPolicy));

        const QUrlQuery form(QString::fromUtf8(body));
        QCOMPARE(form.queryItemValue(QStringLiteral("grant_type")), QStringLiteral("authorization_code"));
        QCOMPARE(form.queryItemValue(QStringLiteral("code")), QStringLiteral("auth-code"));
        QCOMPARE(form.queryItemValue(QStringLiteral("redirect_uri")), config.redirectUri);
        QCOMPARE(form.queryItemValue(QStringLiteral("client_id")), config.clientId);
        QCOMPARE(form.queryItemValue(QStringLiteral("client_secret")), config.clientSecret);
        QCOMPARE(form.queryItemValue(QStringLiteral("code_verifier")), QStringLiteral("pkce-verifier"));
        QCOMPARE(form.queryItemValue(QStringLiteral("audience")), config.audience);
    }

    void validatesAuthorizationCallbackStateAndErrors()
    {
        const QString redirectUri = QStringLiteral("psi-oauth://callback");
        const QString state = QStringLiteral("expected-state");
        QString code;
        QString error;
        bool authorizationError = false;

        QVERIFY(parseIamAuthorizationCallback(
            redirectUri, QUrl(QStringLiteral("psi-oauth://callback?state=expected-state&code=auth-code")),
            state, code, authorizationError, error));
        QCOMPARE(code, QStringLiteral("auth-code"));
        QVERIFY(!authorizationError);
        QVERIFY(error.isEmpty());

        QVERIFY(!parseIamAuthorizationCallback(
            redirectUri, QUrl(QStringLiteral("psi-oauth://callback?state=other&code=auth-code")),
            state, code, authorizationError, error));
        QVERIFY(!error.isEmpty());

        QVERIFY(parseIamAuthorizationCallback(
            redirectUri, QUrl(QStringLiteral("psi-oauth://callback?state=expected-state&error=access_denied")),
            state, code, authorizationError, error));
        QVERIFY(authorizationError);

        QVERIFY(parseIamAuthorizationCallback(redirectUri, QUrl(QStringLiteral("psi-oauth://callback?state=expected-state")),
                                              state, code, authorizationError, error));
        QVERIFY(!error.isEmpty());
    }

    void selectsConfiguredToken()
    {
        const QByteArray response = R"({"access_token":"access-value","id_token":"id-value"})";
        QString           token;
        QString           error;

        QVERIFY(parseIamTokenResponse(response, false, token, error));
        QCOMPARE(token, QStringLiteral("access-value"));
        QVERIFY(parseIamTokenResponse(response, true, token, error));
        QCOMPARE(token, QStringLiteral("id-value"));
        QVERIFY(!parseIamTokenResponse(R"({"access_token":"access-value"})", true, token, error));
        QVERIFY(!error.isEmpty());
    }

    void parsesAndPersistsTokenSetExpiryAndRefreshToken()
    {
        IamTokenSet tokens;
        QString error;
        QVERIFY(parseIamTokenSet(
            R"({"access_token":"access","id_token":"identity","refresh_token":"refresh","expires_in":3600})",
            false, tokens, error));
        QCOMPARE(selectedIamToken(tokens, false), QStringLiteral("access"));
        QCOMPARE(selectedIamToken(tokens, true), QStringLiteral("identity"));
        QCOMPARE(tokens.refreshToken, QStringLiteral("refresh"));
        QVERIFY(isIamAccessTokenValid(tokens));

        IamTokenSet restored;
        QVERIFY(parseStoredIamTokenSet(serializeIamTokenSet(tokens), restored));
        QCOMPARE(restored.accessToken, tokens.accessToken);
        QCOMPARE(restored.idToken, tokens.idToken);
        QCOMPARE(restored.refreshToken, tokens.refreshToken);
        QCOMPARE(restored.expiresAt, tokens.expiresAt);

        restored.expiresAt = QDateTime::currentDateTimeUtc().addSecs(30);
        QVERIFY(!isIamAccessTokenValid(restored));
        QVERIFY(isIamRefreshTokenRejected(R"({"error":"invalid_grant"})"));
        QVERIFY(!isIamRefreshTokenRejected(R"({"error":"temporarily_unavailable"})"));
    }

    void preservesPasswordAuthentication()
    {
        QCOMPARE(authPassword(false, QStringLiteral("existing-password"), QStringLiteral("unused-token")),
                 QStringLiteral("existing-password"));
        QCOMPARE(authPassword(true, QStringLiteral("unused-password"), QStringLiteral("iam-token")),
                 QStringLiteral("iam-token"));
    }

    void createsEjabberdXOAuth2Payload()
    {
        const QByteArray payload = xOauth2SaslInitialResponse(QString(), QStringLiteral("alice"),
                                                              QByteArray("jwt-token"));
        QCOMPARE(payload, QByteArray("\0alice\0jwt-token", 16));

        const QByteArray withAuthzid = xOauth2SaslInitialResponse(QStringLiteral("alice@example.com"),
                                                                  QStringLiteral("alice"),
                                                                  QByteArray("jwt-token"));
        QCOMPARE(withAuthzid, QByteArray("alice@example.com\0alice\0jwt-token", 33));
    }
};

QTEST_GUILESS_MAIN(IamTokenAuthTest)
#include "iamtokenauthtest.moc"
