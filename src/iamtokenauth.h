#ifndef IAMTOKENAUTH_H
#define IAMTOKENAUTH_H

#include <QByteArray>
#include <QDateTime>
#include <QNetworkRequest>
#include <QString>
#include <QUrl>

struct IamTokenAuthConfig {
    QString endpoint;
    QString audience;
    QString clientId;
    QString clientSecret;
    QString scope;
    bool    useIdToken = false;
    QString authorizationEndpoint;
    QString redirectUri;
    bool    useAuthorizationCode = false;
};

struct IamTokenSet {
    QString  accessToken;
    QString  idToken;
    QString  refreshToken;
    QDateTime expiresAt;
};

bool createIamTokenRequest(const IamTokenAuthConfig &config, QNetworkRequest &request, QByteArray &body,
                           QString &error);
bool createIamRefreshTokenRequest(const IamTokenAuthConfig &config, const QString &refreshToken,
                                  QNetworkRequest &request, QByteArray &body, QString &error);
bool createIamAuthorizationRequest(const IamTokenAuthConfig &config, const QString &state,
                                   const QString &codeVerifier, QUrl &authorizationUrl, QString &error);
bool parseIamAuthorizationCallback(const QString &redirectUri, const QUrl &callbackUri,
                                  const QString &expectedState, QString &code, bool &authorizationError,
                                  QString &error);
bool createIamAuthorizationCodeTokenRequest(const IamTokenAuthConfig &config, const QString &code,
                                            const QString &codeVerifier, QNetworkRequest &request, QByteArray &body,
                                            QString &error);
bool parseIamTokenSet(const QByteArray &response, bool useIdToken, IamTokenSet &tokens, QString &error);
bool parseIamTokenResponse(const QByteArray &response, bool useIdToken, QString &token, QString &error);
QByteArray serializeIamTokenSet(const IamTokenSet &tokens);
bool parseStoredIamTokenSet(const QByteArray &stored, IamTokenSet &tokens);
bool isIamAccessTokenValid(const IamTokenSet &tokens, const QDateTime &now = QDateTime::currentDateTimeUtc());
bool isIamRefreshTokenRejected(const QByteArray &response);
QString selectedIamToken(const IamTokenSet &tokens, bool useIdToken);
QString authPassword(bool useIamToken, const QString &password, const QString &token);
QByteArray xOauth2SaslInitialResponse(const QString &authzid, const QString &username, const QByteArray &token);

#endif // IAMTOKENAUTH_H
