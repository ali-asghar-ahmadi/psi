#include "iamtokenauth.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QDateTime>
#include <QCryptographicHash>
#include <QUrl>
#include <QUrlQuery>

namespace {
bool isValidHttpsEndpoint(const QString &value)
{
    const QUrl endpoint(value);
    return endpoint.isValid() && endpoint.scheme() == QLatin1String("https") && !endpoint.host().isEmpty()
        && endpoint.userInfo().isEmpty() && endpoint.fragment().isEmpty();
}

bool isValidIamRedirectUri(const QString &value)
{
    const QUrl uri(value);
    return uri.isValid() && uri.scheme() == QLatin1String("psi-oauth") && !uri.host().isEmpty()
        && uri.userInfo().isEmpty() && !uri.hasQuery() && uri.fragment().isEmpty();
}
}

bool createIamTokenRequest(const IamTokenAuthConfig &config, QNetworkRequest &request, QByteArray &body,
                           QString &error)
{
    const QUrl endpoint(config.endpoint);
    if (!isValidHttpsEndpoint(config.endpoint)) {
        error = QStringLiteral("The OAuth2 token endpoint must be a valid HTTPS URL.");
        return false;
    }
    if (config.clientId.isEmpty() || config.clientSecret.isEmpty()) {
        error = QStringLiteral("OAuth2 client ID and client secret are required.");
        return false;
    }

    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("client_credentials"));
    form.addQueryItem(QStringLiteral("client_id"), config.clientId);
    form.addQueryItem(QStringLiteral("client_secret"), config.clientSecret);
    if (!config.audience.isEmpty())
        form.addQueryItem(QStringLiteral("audience"), config.audience);
    if (!config.scope.isEmpty())
        form.addQueryItem(QStringLiteral("scope"), config.scope);

    request.setUrl(endpoint);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    body = form.query(QUrl::FullyEncoded).toUtf8();
    error.clear();
    return true;
}

bool createIamRefreshTokenRequest(const IamTokenAuthConfig &config, const QString &refreshToken,
                                  QNetworkRequest &request, QByteArray &body, QString &error)
{
    if (!isValidHttpsEndpoint(config.endpoint)) {
        error = QStringLiteral("The OAuth2 token endpoint must be a valid HTTPS URL.");
        return false;
    }
    if (config.clientId.isEmpty() || refreshToken.isEmpty()) {
        error = QStringLiteral("OAuth2 client ID and refresh token are required.");
        return false;
    }

    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("refresh_token"));
    form.addQueryItem(QStringLiteral("refresh_token"), refreshToken);
    form.addQueryItem(QStringLiteral("client_id"), config.clientId);
    if (!config.clientSecret.isEmpty())
        form.addQueryItem(QStringLiteral("client_secret"), config.clientSecret);
    if (!config.audience.isEmpty())
        form.addQueryItem(QStringLiteral("audience"), config.audience);
    if (!config.scope.isEmpty())
        form.addQueryItem(QStringLiteral("scope"), config.scope);

    request.setUrl(QUrl(config.endpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    body = form.query(QUrl::FullyEncoded).toUtf8();
    error.clear();
    return true;
}

bool createIamAuthorizationRequest(const IamTokenAuthConfig &config, const QString &state,
                                   const QString &codeVerifier, QUrl &authorizationUrl, QString &error)
{
    if (!isValidHttpsEndpoint(config.authorizationEndpoint)) {
        error = QStringLiteral("The OAuth2 authorization endpoint must be a valid HTTPS URL.");
        return false;
    }
    if (!isValidIamRedirectUri(config.redirectUri)) {
        error = QStringLiteral("The redirect URI must use the registered psi-oauth:// scheme.");
        return false;
    }
    if (config.clientId.isEmpty() || state.isEmpty() || codeVerifier.isEmpty()) {
        error = QStringLiteral("OAuth2 client ID and PKCE parameters are required.");
        return false;
    }

    authorizationUrl = QUrl(config.authorizationEndpoint);
    QUrlQuery query(authorizationUrl);
    query.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
    query.addQueryItem(QStringLiteral("client_id"), config.clientId);
    query.addQueryItem(QStringLiteral("redirect_uri"), config.redirectUri);
    query.addQueryItem(QStringLiteral("state"), state);
    const QByteArray challenge
        = QCryptographicHash::hash(codeVerifier.toUtf8(), QCryptographicHash::Sha256)
              .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    query.addQueryItem(QStringLiteral("code_challenge"), QString::fromLatin1(challenge));
    query.addQueryItem(QStringLiteral("code_challenge_method"), QStringLiteral("S256"));
    if (!config.audience.isEmpty())
        query.addQueryItem(QStringLiteral("audience"), config.audience);
    if (!config.scope.isEmpty())
        query.addQueryItem(QStringLiteral("scope"), config.scope);
    authorizationUrl.setQuery(query);
    error.clear();
    return true;
}

bool parseIamAuthorizationCallback(const QString &redirectUri, const QUrl &callbackUri,
                                   const QString &expectedState, QString &code, bool &authorizationError,
                                   QString &error)
{
    code.clear();
    authorizationError = false;
    error.clear();

    const QUrl expected(redirectUri);
    if (!isValidIamRedirectUri(redirectUri) || !callbackUri.isValid() || expectedState.isEmpty()
        || callbackUri.scheme() != expected.scheme()
        || callbackUri.host() != expected.host() || callbackUri.port() != expected.port()
        || callbackUri.path() != expected.path() || !callbackUri.userInfo().isEmpty()
        || callbackUri.hasFragment()) {
        error = QStringLiteral("The OAuth2 callback URI does not match the configured redirect URI.");
        return false;
    }

    const QUrlQuery query(callbackUri);
    const QStringList states = query.allQueryItemValues(QStringLiteral("state"));
    if (states.size() != 1 || states.constFirst() != expectedState) {
        error = QStringLiteral("The OAuth2 callback state did not match.");
        return false;
    }

    const QStringList oauthErrors = query.allQueryItemValues(QStringLiteral("error"));
    if (!oauthErrors.isEmpty()) {
        authorizationError = true;
        return true;
    }

    const QStringList codes = query.allQueryItemValues(QStringLiteral("code"));
    if (codes.size() != 1 || codes.constFirst().isEmpty()) {
        error = QStringLiteral("The OAuth2 callback did not contain an authorization code.");
        return true;
    }

    code = codes.constFirst();
    return true;
}

bool createIamAuthorizationCodeTokenRequest(const IamTokenAuthConfig &config, const QString &code,
                                            const QString &codeVerifier, QNetworkRequest &request, QByteArray &body,
                                            QString &error)
{
    if (!isValidHttpsEndpoint(config.endpoint)) {
        error = QStringLiteral("The OAuth2 token endpoint must be a valid HTTPS URL.");
        return false;
    }
    if (!isValidIamRedirectUri(config.redirectUri)) {
        error = QStringLiteral("The redirect URI must use the registered psi-oauth:// scheme.");
        return false;
    }
    if (config.clientId.isEmpty() || code.isEmpty() || codeVerifier.isEmpty()) {
        error = QStringLiteral("OAuth2 client ID, authorization code, and PKCE verifier are required.");
        return false;
    }

    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("authorization_code"));
    form.addQueryItem(QStringLiteral("code"), code);
    form.addQueryItem(QStringLiteral("redirect_uri"), config.redirectUri);
    form.addQueryItem(QStringLiteral("client_id"), config.clientId);
    form.addQueryItem(QStringLiteral("code_verifier"), codeVerifier);
    if (!config.clientSecret.isEmpty())
        form.addQueryItem(QStringLiteral("client_secret"), config.clientSecret);
    if (!config.audience.isEmpty())
        form.addQueryItem(QStringLiteral("audience"), config.audience);

    request.setUrl(QUrl(config.endpoint));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    body = form.query(QUrl::FullyEncoded).toUtf8();
    error.clear();
    return true;
}

bool parseIamTokenSet(const QByteArray &response, bool useIdToken, IamTokenSet &tokens, QString &error)
{
    tokens = IamTokenSet();
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(response, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        error = QStringLiteral("The OAuth2 token response was not valid JSON.");
        return false;
    }

    const QJsonObject object = document.object();
    const QJsonValue accessToken = object.value(QStringLiteral("access_token"));
    const QJsonValue idToken = object.value(QStringLiteral("id_token"));
    const QJsonValue refreshToken = object.value(QStringLiteral("refresh_token"));
    if (accessToken.isString())
        tokens.accessToken = accessToken.toString();
    if (idToken.isString())
        tokens.idToken = idToken.toString();
    if (refreshToken.isString())
        tokens.refreshToken = refreshToken.toString();

    const QJsonValue expiresIn = object.value(QStringLiteral("expires_in"));
    bool expiresInOk = false;
    const qint64 expiresInSeconds = expiresIn.toVariant().toLongLong(&expiresInOk);
    if (expiresInOk && expiresInSeconds > 0)
        tokens.expiresAt = QDateTime::currentDateTimeUtc().addSecs(expiresInSeconds);

    if (selectedIamToken(tokens, useIdToken).isEmpty()) {
        error = QStringLiteral("The selected token was missing from the OAuth2 response.");
        return false;
    }

    error.clear();
    return true;
}

bool parseIamTokenResponse(const QByteArray &response, bool useIdToken, QString &token, QString &error)
{
    IamTokenSet tokens;
    if (!parseIamTokenSet(response, useIdToken, tokens, error)) {
        token.clear();
        return false;
    }
    token = selectedIamToken(tokens, useIdToken);
    return true;
}

QByteArray serializeIamTokenSet(const IamTokenSet &tokens)
{
    QJsonObject object;
    object.insert(QStringLiteral("access_token"), tokens.accessToken);
    object.insert(QStringLiteral("id_token"), tokens.idToken);
    object.insert(QStringLiteral("refresh_token"), tokens.refreshToken);
    object.insert(QStringLiteral("expires_at"), tokens.expiresAt.toString(Qt::ISODateWithMs));
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

bool parseStoredIamTokenSet(const QByteArray &stored, IamTokenSet &tokens)
{
    tokens = IamTokenSet();
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(stored, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
        return false;

    const QJsonObject object = document.object();
    tokens.accessToken = object.value(QStringLiteral("access_token")).toString();
    tokens.idToken = object.value(QStringLiteral("id_token")).toString();
    tokens.refreshToken = object.value(QStringLiteral("refresh_token")).toString();
    tokens.expiresAt = QDateTime::fromString(object.value(QStringLiteral("expires_at")).toString(), Qt::ISODateWithMs);
    return !tokens.accessToken.isEmpty() || !tokens.idToken.isEmpty() || !tokens.refreshToken.isEmpty();
}

bool isIamAccessTokenValid(const IamTokenSet &tokens, const QDateTime &now)
{
    return (!tokens.accessToken.isEmpty() || !tokens.idToken.isEmpty()) && tokens.expiresAt.isValid()
        && tokens.expiresAt > now.addSecs(60);
}

bool isIamRefreshTokenRejected(const QByteArray &response)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(response, &parseError);
    return parseError.error == QJsonParseError::NoError && document.isObject()
        && document.object().value(QStringLiteral("error")).toString() == QLatin1String("invalid_grant");
}

QString selectedIamToken(const IamTokenSet &tokens, bool useIdToken)
{
    return useIdToken ? tokens.idToken : tokens.accessToken;
}

QString authPassword(bool useIamToken, const QString &password, const QString &token)
{
    return useIamToken ? token : password;
}

QByteArray xOauth2SaslInitialResponse(const QString &authzid, const QString &username, const QByteArray &token)
{
    QByteArray response = authzid.toUtf8();
    response += '\0';
    response += username.toUtf8();
    response += '\0';
    response += token;
    return response;
}
