/*
Copyright (C) 2010, 2014 Srivats P.

This file is part of "Ostinato"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#include "sslconfig.h"
#include "ssl.h"

#include <QDebug>

SslConfigForm::SslConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    setupUi(this);
}

SslConfigForm::~SslConfigForm()
{
}

SslConfigForm* SslConfigForm::createInstance()
{
    return new SslConfigForm;
}

/*!
TODO: Edit this function to load each field's data into the config Widget

See AbstractProtocolConfigForm::loadWidget() for more info
*/
void SslConfigForm::loadWidget(AbstractProtocol *proto)
{
    bool isOk;

    leSslVersion->setText(
        proto->fieldData(
            SslProtocol::ssl_version,
            AbstractProtocol::FieldValue
        ).toString());

    leSslPayloadLength->setText(
        proto->fieldData(
            SslProtocol::ssl_payloadLength,
            AbstractProtocol::FieldValue
        ).toString());

    cbSslType->setCurrentIndex(
        getFieldIndex(
            SslProtocol,
            proto->fieldData(
                SslProtocol::ssl_type,
                    AbstractProtocol::FieldValue
        ).toString()));

    leAlertSeverity->setText(
        proto->fieldData(
            SslProtocol::ssl_alert_message,
                AbstractProtocol::FieldValue
        ).toString().left(2));

    leAlertDescription->setText(
        proto->fieldData(
            SslProtocol::ssl_alert_message,
                AbstractProtocol::FieldValue
        ).toString().right(2));

    cbHandshakeType->setCurrentIndex(
        getFieldIndex(
            HandshakeProtocol,
            proto->fieldData(
                SslProtocol::ssl_handshake_type,
                AbstractProtocol::FieldValue
        ).toString()));

    leHandshakeLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_length,
            AbstractProtocol::FieldValue
        ).toString());

    leHandshakeVersion->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_version,
            AbstractProtocol::FieldValue
        ).toString());

    leRandomTime->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_random,
            AbstractProtocol::FieldValue
        ).toString().left(8));

    leRandomBytes->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_random,
            AbstractProtocol::FieldValue
        ).toString().right(56));

    leSessionIDLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_sessionIdLen,
            AbstractProtocol::FieldValue
        ).toString());

    leSessionID->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_sessionId,
            AbstractProtocol::FieldValue
        ).toString());

    leCipherSuitesLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_ciphersuitesLen,
            AbstractProtocol::FieldValue
        ).toString());

    leCompressionLength->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_compMethodsLen,
            AbstractProtocol::FieldValue
        ).toString());

    leExtensionsLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_extensionsLen,
            AbstractProtocol::FieldValue
        ).toString());

    leCertLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_certificatesLen,
            AbstractProtocol::FieldValue
        ).toString());

        // ciphersuite
        {
            int handshakeType = proto->fieldData(SslProtocol::ssl_handshake_type,
                                                 AbstractProtocol::FieldValue).toString().toInt(&isOk, 16);
            QStringList ciphersuites = proto->fieldData(SslProtocol::ssl_handshake_ciphersuite,
                                                        AbstractProtocol::FieldValue).toStringList();

            if(handshakeType == ClientHello)
            {
                teCipherSuites->setPlainText(ciphersuites.join("\n"));
            }
            else if (handshakeType == ServerHello)
            {
                leSHelloCipher->setText(ciphersuites[0]);
            }
        }

        // comp method
        {
            int handshakeType = proto->fieldData(SslProtocol::ssl_handshake_type,
                                             AbstractProtocol::FieldValue).toString().toInt(&isOk, 16);
            QStringList compMethods = proto->fieldData(SslProtocol::ssl_handshake_compMethod,
                                                   AbstractProtocol::FieldValue).toStringList();
            if(handshakeType == ClientHello)
            {
                teCompMethods->setPlainText(compMethods.join("\n"));
            }
            else if (handshakeType == ServerHello)
            {
                leSHelloComp->setText(compMethods[0]);
            }

        }

        // extentions
        {
            QStringList extensions = proto->fieldData(
                        SslProtocol::ssl_handshake_extension,
                        AbstractProtocol::FieldValue).toStringList();

            teExtensions->setPlainText(extensions.join("\n"));

        }

        // certificates
        {
            QStringList certificates = proto->fieldData(
                        SslProtocol::ssl_handshake_certificate,
                        AbstractProtocol::FieldValue).toStringList();

            teCertificates->setPlainText(certificates.join("\n"));

        }

    leClientKeyLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_keyLen,
            AbstractProtocol::FieldValue
        ).toString());

    teClientKey->setPlainText(
        proto->fieldData(
            SslProtocol::ssl_handshake_key,
            AbstractProtocol::FieldValue
        ).toString());

    // application data
    {
        teAppData->setPlainText(
            proto->fieldData(
                SslProtocol::ssl_appData,
                AbstractProtocol::FieldValue
            ).toString());
    }

    leCertTypesCount->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_certificateTypesCount,
            AbstractProtocol::FieldValue
        ).toString());

    leDistNamesLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_distinguishedNamesLen,
            AbstractProtocol::FieldValue
        ).toString());

    // certificate type
    {
        int handshakeType = proto->fieldData(SslProtocol::ssl_handshake_type,
                                             AbstractProtocol::FieldValue).toString().toInt(&isOk, 16);
        QStringList ciphersuites = proto->fieldData(SslProtocol::ssl_handshake_certificateType,
                                                    AbstractProtocol::FieldValue).toStringList();

        if(handshakeType == CertificateRequest)
        {
            teCertTypes->setPlainText(ciphersuites.join("\n"));
        }
    }

    // distinguished name
    {
        QStringList distNames = proto->fieldData(
                    SslProtocol::ssl_handshake_distinguishedName,
                    AbstractProtocol::FieldValue).toStringList();

        teDistNames->setPlainText(distNames.join("\n"));

    }

    leSignLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_signatureLen,
            AbstractProtocol::FieldValue
        ).toString());
    teSignature->setPlainText(
        proto->fieldData(
            SslProtocol::ssl_handshake_signature,
            AbstractProtocol::FieldValue
        ).toString());

}

/*!
TODO: Edit this function to store each field's data from the config Widget

See AbstractProtocolConfigForm::storeWidget() for more info
*/
void SslConfigForm::storeWidget(AbstractProtocol *proto)
{
    bool isOk;

    proto->setFieldData(
        SslProtocol::ssl_type,
        getFieldValue(SslProtocol, cbSslType->currentIndex()));

    proto->setFieldData(
        SslProtocol::ssl_version,
        leSslVersion->text().toInt(&isOk, 16));

    proto->setFieldData(
        SslProtocol::ssl_payloadLength,
        leSslPayloadLength->text());

    if(cbSslType->currentIndex() == 0)
        proto->setFieldData(SslProtocol::ssl_ccs, 1);

    if(cbSslType->currentIndex() == 1)
    {
        proto->setFieldData(
            SslProtocol::ssl_alert_message,
            (leAlertSeverity->text().toInt(&isOk, 16) << 8) |
            (leAlertDescription->text().toInt(&isOk, 16) & 0xFF));
    }
    if(cbSslType->currentIndex() == 2)
    {
        proto->setFieldData(
            SslProtocol::ssl_handshake_type,
            getFieldValue(HandshakeProtocol,
                cbHandshakeType->currentIndex()));

        proto->setFieldData(
            SslProtocol::ssl_handshake_length,
            leHandshakeLen->text());

        proto->setFieldData(
            SslProtocol::ssl_handshake_version,
            leHandshakeVersion->text().toInt(&isOk, 16));

        proto->setFieldData(
            SslProtocol::ssl_handshake_random,
            (leRandomTime->text()).append(leRandomBytes->text()));

        proto->setFieldData(
            SslProtocol::ssl_handshake_sessionIdLen,
            leSessionIDLen->text().toInt(&isOk, 10));

        proto->setFieldData(
            SslProtocol::ssl_handshake_sessionId,
            leSessionID->text());

        proto->setFieldData(
            SslProtocol::ssl_handshake_ciphersuitesLen,
            leCipherSuitesLen->text().toInt(&isOk, 10));

        proto->setFieldData(
            SslProtocol::ssl_handshake_compMethodsLen,
            leCompressionLength->text().toInt(&isOk, 10));

        proto->setFieldData(
            SslProtocol::ssl_handshake_extensionsLen,
            leExtensionsLen->text().toInt(&isOk, 10));

        proto->setFieldData(
            SslProtocol::ssl_handshake_certificatesLen,
            leCertLen->text().toInt(&isOk, 16));

        // ciphersuite
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if(handshakeType == ClientHello)
            {
                QStringList list = teCipherSuites->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_ciphersuite,
                    list);
            }
            else if(handshakeType == ServerHello)
            {
                QStringList list;
                list << leSHelloCipher->text();
                proto->setFieldData(
                    SslProtocol::ssl_handshake_ciphersuite,
                    list);
            }

        }

        // compmethod
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if(handshakeType == ClientHello)
            {
                QStringList list = teCompMethods->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_compMethod,
                    list);
            }
            else if(handshakeType == ServerHello)
            {
                QStringList list;
                list << leSHelloComp->text();
                proto->setFieldData(
                    SslProtocol::ssl_handshake_compMethod,
                    list);
            }
        }

        // extensions
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if (handshakeType == ClientHello || handshakeType == ServerHello)
            {
                QStringList list = teExtensions->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_extension,
                    list);
            }
        }

        // certificates
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if (handshakeType == Certificate)
            {
                QStringList list = teCertificates->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_certificate,
                    list);
            }
        }

        proto->setFieldData(
            SslProtocol::ssl_handshake_keyLen,
            leClientKeyLen->text().toInt(&isOk, 10));

        // key
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if (handshakeType == ClientKeyExchange || handshakeType == ServerKeyExchange)
            {
                proto->setFieldData(
                    SslProtocol::ssl_handshake_key,
                    teClientKey->toPlainText());
            }
        }

        proto->setFieldData(
            SslProtocol::ssl_handshake_certificateTypesCount,
            leCertTypesCount->text().toUInt(&isOk, 10));

        proto->setFieldData(
            SslProtocol::ssl_handshake_distinguishedNamesLen,
            leDistNamesLen->text().toUInt(&isOk, 10));

        // certificate type
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if(handshakeType == CertificateRequest)
            {
                QStringList list = teCertTypes->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_certificateType,
                    list);
            }

        }

        // distinguished names
        {
            int handshakeType = getFieldValue(HandshakeProtocol, cbHandshakeType->currentIndex());
            if (handshakeType == CertificateRequest)
            {
                QStringList list = teDistNames->toPlainText().split('\n');
                proto->setFieldData(
                    SslProtocol::ssl_handshake_distinguishedName,
                    list);
            }
        }

        proto->setFieldData(
            SslProtocol::ssl_handshake_signatureLen,
            leSignLen->text());
        proto->setFieldData(
            SslProtocol::ssl_handshake_signature,
            teSignature->toPlainText());

    }

    // application data
    if(cbSslType->currentIndex() == 3)
    {
        proto->setFieldData(
            SslProtocol::ssl_appData,
            teAppData->toPlainText());
    }

}

int SslConfigForm::getFieldIndex(int field, QString value)
{
    bool isOk;
    int index = value.toInt(&isOk, 16);

    switch (field)
    {
        case SslProtocol:
        {
            switch (index)
            {
            case CCS:
                return 0;
            case Alert:
                return 1;
            case Handshake:
                return 2;
            case AppData:
                return 3;
            default:
                return -1;
            }
            break;
        }
        case HandshakeProtocol:
        {
            switch(index)
            {
            case HelloRequest:
                return 0;
            case ClientHello:
                return 1;
            case ServerHello:
                return 2;
            case Certificate:
                return 3;
            case ServerKeyExchange:
                return 4;
            case CertificateRequest:
                return 5;
            case ServerHelloDone:
                return 6;
            case CertificateVerify:
                return 7;
            case ClientKeyExchange:
                return 8;
            case Finished:
                return 9;
            }
            break;
        }
    }
    return -1;
}

int SslConfigForm::getFieldValue(int field, int index)
{
    switch (field)
    {
        case SslProtocol:
        {
            switch (index)
            {
            case 0:
                return CCS;
            case 1:
                return Alert;
            case 2:
                return Handshake;
            case 3:
                return AppData;
            default:
                return -1;
            }
            break;
        }
        case HandshakeProtocol:
        {
        qDebug("indexKarthik");
        qDebug() << index;
        qDebug("index");

            switch (index)
            {
            case 0:
                return HelloRequest;
            case 1:
                return ClientHello;
            case 2:
                return ServerHello;
            case 3:
                return Certificate;
            case 4:
                return ServerKeyExchange;
            case 5:
                return CertificateRequest;
            case 6:
                return ServerHelloDone;
            case 7:
                return CertificateVerify;
            case 8:
                return ClientKeyExchange;
            case 9:
                return Finished;
            }
            break;
        }
    }
    return -1;
}

void SslConfigForm::on_cbHandshakeType_currentIndexChanged(int index)
{
    switch (index) {
    case 0:
    case 6:
    case 9:
        swHandshake->setCurrentIndex(0);
        leHandshakeVersion->hide();
        labelHandshakeVersion->hide();
        break;
    case 1:
        swHandshake->setCurrentIndex(1);
        swHello->setCurrentIndex(0);
        leHandshakeVersion->show();
        labelHandshakeVersion->show();
        break;
    case 2:
        swHandshake->setCurrentIndex(1);
        swHello->setCurrentIndex(1);
        leHandshakeVersion->show();
        labelHandshakeVersion->show();
        break;
    case 3:
        swHandshake->setCurrentIndex(2);
        leHandshakeVersion->hide();
        labelHandshakeVersion->hide();
        break;
    case 4:
    case 8:
        swHandshake->setCurrentIndex(3);
        leHandshakeVersion->hide();
        labelHandshakeVersion->hide();
        break;
    case 5:
        swHandshake->setCurrentIndex(4);
        leHandshakeVersion->hide();
        labelHandshakeVersion->hide();
    case 7:
        swHandshake->setCurrentIndex(5);
        leHandshakeVersion->hide();
        labelHandshakeVersion->hide();
    }
}
