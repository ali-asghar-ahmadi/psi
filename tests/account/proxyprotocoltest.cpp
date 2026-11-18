/*
 * proxyprotocoltest.cpp - PROXY protocol v1 header tests
 * Copyright (C) 2026  The Psi+ Project
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "proxyprotocol.h"
#include <xmpp.h>
#include <iris/jid/jid.h>
#include <iris/xmpp-core/xmpp_clientstream.h>

#include <QtTest/QtTest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSignalSpy>

class ProxyProtocolTest : public QObject {
    Q_OBJECT

private slots:
    void createsIpv4Header();
    void createsIpv6HeaderWithoutScopeIds();
    void rejectsUnsupportedAddressPairs();
    void sendsHeaderBeforeStreamData();
    void rejectsConnectionProxy();
    void reportsMissingTlsHandlerWithoutCrashing();
};

void ProxyProtocolTest::createsIpv4Header()
{
    QByteArray header;
    QVERIFY(XMPP::createProxyProtocolV1Header(QHostAddress(QStringLiteral("192.0.2.1")), 12345,
                                              QHostAddress(QStringLiteral("198.51.100.2")), 5222, header));
    QCOMPARE(header, QByteArrayLiteral("PROXY TCP4 192.0.2.1 198.51.100.2 12345 5222\r\n"));
}

void ProxyProtocolTest::createsIpv6HeaderWithoutScopeIds()
{
    QHostAddress source(QStringLiteral("fe80::1"));
    source.setScopeId(QStringLiteral("eth0"));
    QHostAddress destination(QStringLiteral("2001:db8::2"));
    QByteArray header;
    QVERIFY(XMPP::createProxyProtocolV1Header(source, 12345, destination, 5222, header));
    QCOMPARE(header, QByteArrayLiteral("PROXY TCP6 fe80::1 2001:db8::2 12345 5222\r\n"));
}

void ProxyProtocolTest::rejectsUnsupportedAddressPairs()
{
    QByteArray header = QByteArrayLiteral("old data");
    QString error;
    QVERIFY(!XMPP::createProxyProtocolV1Header(QHostAddress(QStringLiteral("192.0.2.1")), 12345,
                                               QHostAddress(QStringLiteral("2001:db8::2")), 5222, header, &error));
    QVERIFY(header.isEmpty());
    QVERIFY(!error.isEmpty());

    QVERIFY(!XMPP::createProxyProtocolV1Header(QHostAddress(), 12345, QHostAddress(), 5222, header, &error));
    QVERIFY(header.isEmpty());
}

void ProxyProtocolTest::sendsHeaderBeforeStreamData()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));

    XMPP::AdvancedConnector connector;
    connector.setOptHostPort(QStringLiteral("127.0.0.1"), server.serverPort());
    connector.setOptProxyProtocol(true);
    connector.connectToServer(QStringLiteral("example.org"));

    QTRY_VERIFY(server.hasPendingConnections());
    QTcpSocket *socket = server.nextPendingConnection();
    QVERIFY(socket);
    QTRY_VERIFY(socket->bytesAvailable() > 0);

    QByteArray expected;
    QVERIFY(XMPP::createProxyProtocolV1Header(socket->peerAddress(), socket->peerPort(), socket->localAddress(),
                                              socket->localPort(), expected));
    QCOMPARE(socket->readAll(), expected);
}

void ProxyProtocolTest::rejectsConnectionProxy()
{
    XMPP::AdvancedConnector connector;
    XMPP::AdvancedConnector::Proxy proxy;
    proxy.setHttpConnect(QStringLiteral("127.0.0.1"), 8080);
    connector.setProxy(proxy);
    connector.setOptProxyProtocol(true);

    QSignalSpy errorSpy(&connector, &XMPP::Connector::error);
    connector.connectToServer(QStringLiteral("example.org"));

    QCOMPARE(errorSpy.count(), 1);
    QCOMPARE(connector.errorCode(), int(XMPP::AdvancedConnector::ErrProxyProtocol));
}

void ProxyProtocolTest::reportsMissingTlsHandlerWithoutCrashing()
{
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));

    XMPP::AdvancedConnector connector;
    connector.setOptHostPort(QStringLiteral("127.0.0.1"), server.serverPort());
    connector.setOptSSL(true);
    XMPP::ClientStream stream(&connector);
    QSignalSpy errorSpy(&stream, SIGNAL(error(int)));

    stream.connectToServer(XMPP::Jid(QStringLiteral("user@example.org")), false);

    QTRY_COMPARE(errorSpy.count(), 1);
    QCOMPARE(errorSpy.takeFirst().at(0).toInt(), int(XMPP::ClientStream::ErrTLS));
}

QTEST_GUILESS_MAIN(ProxyProtocolTest)

#include "proxyprotocoltest.moc"
