#include "iamtokenauth.h"
#include "iamtokenoauthsasl.h"

#include <QEventLoop>
#include <QTimer>
#include <QtCrypto>
#include <QtTest>

#ifdef HAVE_BUNDLED_IRIS
#include "../../iris/src/xmpp/xmpp-core/simplesasl.h"
#endif

class IamTokenOAuthSaslTest : public QObject {
    Q_OBJECT

private slots:
    void sendsXOAuth2MechanismAndInitialResponse()
    {
        QCA::Initializer qca;
        registerIamOAuthSaslProvider();

        QCA::SASL sasl(nullptr, QStringLiteral("psi-iam-oauth"));
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        bool timedOut = false;
        bool failed = false;
        bool hasInitialResponse = false;
        QByteArray initialResponse;

        connect(&sasl, &QCA::SASL::needParams, &sasl, [&sasl](const QCA::SASL::Params &params) {
            if (params.needUsername())
                sasl.setUsername(QStringLiteral("alice"));
            if (params.needPassword())
                sasl.setPassword(QCA::SecureArray(QByteArray("jwt-token")));
            sasl.continueAfterParams();
        });
        connect(&sasl, &QCA::SASL::clientStarted, &loop, [&](bool clientInit, const QByteArray &data) {
            hasInitialResponse = clientInit;
            initialResponse = data;
            loop.quit();
        });
        connect(&sasl, &QCA::SASL::error, &loop, [&]() {
            failed = true;
            loop.quit();
        });
        connect(&timeout, &QTimer::timeout, &loop, [&]() {
            timedOut = true;
            loop.quit();
        });

        sasl.setConstraints(QCA::SASL::AuthFlagsNone, 0, 256);
        sasl.startClient(QStringLiteral("xmpp"), QStringLiteral("example.test"),
                         { QStringLiteral("X-OAUTH2") }, QCA::SASL::AllowClientSendFirst);
        timeout.start(5000);
        loop.exec();

        QVERIFY2(!timedOut, "QCA SASL provider did not finish starting");
        QVERIFY2(!failed, "QCA SASL provider failed to start");
        QCOMPARE(sasl.mechanism(), QStringLiteral("X-OAUTH2"));
        QVERIFY(hasInitialResponse);
        QCOMPARE(initialResponse, QByteArray("\0alice\0jwt-token", 16));
    }

#ifdef HAVE_BUNDLED_IRIS
    void sendsPlainMechanismAndTokenAsPassword()
    {
        QCA::Initializer qca;
        bool             providerFound = false;
        for (QCA::Provider *provider : QCA::providers()) {
            if (provider->name() == QLatin1String("simplesasl")) {
                providerFound = true;
                break;
            }
        }
        if (!providerFound)
            QCA::insertProvider(XMPP::createProviderSimpleSASL());

        QCA::SASL sasl(nullptr, QStringLiteral("simplesasl"));
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        bool timedOut = false;
        bool failed = false;
        bool hasInitialResponse = false;
        QByteArray initialResponse;

        connect(&sasl, &QCA::SASL::needParams, &sasl, [&sasl](const QCA::SASL::Params &params) {
            if (params.needUsername())
                sasl.setUsername(QStringLiteral("alice"));
            if (params.needPassword())
                sasl.setPassword(QCA::SecureArray(QByteArray("jwt-token")));
            sasl.continueAfterParams();
        });
        connect(&sasl, &QCA::SASL::clientStarted, &loop, [&](bool clientInit, const QByteArray &data) {
            hasInitialResponse = clientInit;
            initialResponse = data;
            loop.quit();
        });
        connect(&sasl, &QCA::SASL::error, &loop, [&]() {
            failed = true;
            loop.quit();
        });
        connect(&timeout, &QTimer::timeout, &loop, [&]() {
            timedOut = true;
            loop.quit();
        });

        sasl.setConstraints(QCA::SASL::AllowPlain, 0, 256);
        sasl.startClient(QStringLiteral("xmpp"), QStringLiteral("example.test"),
                         { QStringLiteral("PLAIN") }, QCA::SASL::AllowClientSendFirst);
        timeout.start(5000);
        loop.exec();

        QVERIFY2(!timedOut, "QCA SASL provider did not finish starting");
        QVERIFY2(!failed, "QCA SASL provider failed to start");
        QCOMPARE(sasl.mechanism(), QStringLiteral("PLAIN"));
        QVERIFY(hasInitialResponse);
        QCOMPARE(initialResponse, QByteArray("\0alice\0jwt-token", 16));
    }
#endif
};

QTEST_GUILESS_MAIN(IamTokenOAuthSaslTest)
#include "iamtokenoauthsasltest.moc"
