#include "iamtokenoauthsasl.h"

#include "iamtokenauth.h"

#include <QtCrypto>

namespace {
class IamOAuthSaslContext : public QCA::SASLContext {
public:
    explicit IamOAuthSaslContext(QCA::Provider *provider) : QCA::SASLContext(provider) { reset(); }

    void reset() override
    {
        result_        = Error;
        condition_     = QCA::SASL::NoMechanism;
        mechanism_.clear();
        payload_.clear();
        username_.clear();
        authzid_.clear();
        password_.clear();
        haveUsername_ = false;
        havePassword_ = false;
        needUsername_ = false;
        needPassword_ = false;
        capable_      = true;
    }

    void setup(const QString &, const QString &, const HostPort *, const HostPort *, const QString &, int) override { }

    void setConstraints(QCA::SASL::AuthFlags flags, int minSsf, int) override
    {
        capable_ = !(flags & (QCA::SASL::RequireForwardSecrecy | QCA::SASL::RequirePassCredentials
                             | QCA::SASL::RequireMutualAuth)
                     || minSsf > 0);
    }

    void startClient(const QStringList &mechanisms, bool) override
    {
        if (!capable_ || !mechanisms.contains(QStringLiteral("X-OAUTH2"))) {
            result_    = Error;
            condition_ = capable_ ? QCA::SASL::NoMechanism : QCA::SASL::TooWeak;
        } else {
            mechanism_    = QStringLiteral("X-OAUTH2");
            needUsername_ = !haveUsername_;
            needPassword_ = !havePassword_;
            result_       = (needUsername_ || needPassword_) ? Params : Error;
        }
        notifyResultsReady();
    }

    void startServer(const QString &, bool) override { fail(); }
    void serverFirstStep(const QString &, const QByteArray *) override { fail(); }
    void nextStep(const QByteArray &) override { fail(); }

    void tryAgain() override
    {
        if (mechanism_ != QLatin1String("X-OAUTH2") || !haveUsername_ || !havePassword_) {
            fail();
            return;
        }
        payload_ = xOauth2SaslInitialResponse(authzid_, username_, password_.toByteArray());
        result_  = Success;
        notifyResultsReady();
    }

    void update(const QByteArray &, const QByteArray &) override { fail(); }
    bool waitForResultsReady(int) override { return true; }
    Result result() const override { return result_; }
    QStringList mechlist() const override { return {}; }
    QString mech() const override { return mechanism_; }
    bool haveClientInit() const override { return mechanism_ == QLatin1String("X-OAUTH2"); }
    QByteArray stepData() const override { return payload_; }
    QByteArray to_net() override { return {}; }
    int encoded() const override { return 0; }
    QByteArray to_app() override { return {}; }
    int ssf() const override { return 0; }
    QCA::SASL::AuthCondition authCondition() const override { return condition_; }
    QCA::SASL::Params clientParams() const override
    {
        return QCA::SASL::Params(needUsername_, false, needPassword_, false);
    }

    void setClientParams(const QString *username, const QString *authzid, const QCA::SecureArray *password,
                         const QString *) override
    {
        if (username) {
            username_      = *username;
            haveUsername_  = true;
            needUsername_  = false;
        }
        if (authzid)
            authzid_ = *authzid;
        if (password) {
            password_     = *password;
            havePassword_ = true;
            needPassword_ = false;
        }
    }

    QStringList realmlist() const override { return {}; }
    QString username() const override { return {}; }
    QString authzid() const override { return {}; }
    QCA::Provider::Context *clone() const override { return new IamOAuthSaslContext(provider()); }

private:
    void notifyResultsReady() { QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection); }

    void fail()
    {
        result_    = Error;
        condition_ = QCA::SASL::BadProtocol;
        notifyResultsReady();
    }

    Result                  result_ = Error;
    QCA::SASL::AuthCondition condition_ = QCA::SASL::NoMechanism;
    QString                 mechanism_;
    QByteArray              payload_;
    QString                 username_;
    QString                 authzid_;
    QCA::SecureArray        password_;
    bool                    capable_ = true;
    bool                    haveUsername_ = false;
    bool                    havePassword_ = false;
    bool                    needUsername_ = false;
    bool                    needPassword_ = false;
};

class IamOAuthSaslProvider : public QCA::Provider {
public:
    QString name() const override { return QStringLiteral("psi-iam-oauth"); }
    QStringList features() const override { return { QStringLiteral("sasl") }; }
    int qcaVersion() const override { return QCA_VERSION; }
    QCA::Provider::Context *createContext(const QString &capability) override
    {
        return capability == QLatin1String("sasl") ? new IamOAuthSaslContext(this) : nullptr;
    }
};
}

void registerIamOAuthSaslProvider()
{
    for (QCA::Provider *provider : QCA::providers()) {
        if (provider->name() == QLatin1String("psi-iam-oauth"))
            return;
    }
    QCA::insertProvider(new IamOAuthSaslProvider);
}
