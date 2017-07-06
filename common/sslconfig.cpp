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
//    bool isOk;

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
            FieldName::SslProtocol,
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
            FieldName::HandshakeProtocol,
            proto->fieldData(
                SslProtocol::ssl_handshake_type,
                AbstractProtocol::FieldValue
        ).toString()));

    leHandshakeLen->setText(
        proto->fieldData(
            SslProtocol::ssl_handshake_length,
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
        getFieldValue(FieldName::SslProtocol, cbSslType->currentIndex()));

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
            getFieldValue(FieldName::HandshakeProtocol,
                cbHandshakeType->currentIndex()));

        proto->setFieldData(
            SslProtocol::ssl_handshake_length,
            leHandshakeLen->text());
    }

}

int SslConfigForm::getFieldIndex(int field, QString value)
{
    bool isOk;
    int index = value.toInt(&isOk, 16);

    switch (field)
    {
        case FieldName::SslProtocol:
        {
            switch (index)
            {
            case SslType::CCS:
                return 0;
            case SslType::Alert:
                return 1;
            case SslType::Handshake:
                return 2;
            case SslType::AppData:
                return 3;
            default:
                qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                    index);
                break;
            }
            break;
        }
        case FieldName::HandshakeProtocol:
        {
            switch(index)
            {
            case Handshake::HelloRequest:
                return 0;
            case Handshake::ClientHello:
                return 1;
            case Handshake::ServerHello:
                return 2;
            case Handshake::Certificate:
                return 3;
            case Handshake::ServerKeyExchange:
                return 4;
            case Handshake::CertificateRequest:
                return 5;
            case Handshake::ServerHelloDone:
                return 6;
            case Handshake::CertificateVerify:
                return 7;
            case Handshake::ClientKeyExchange:
                return 8;
            case Handshake::Finished:
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
        case FieldName::SslProtocol:
        {
            switch (index)
            {
            case 0:
                return SslType::CCS;
            case 1:
                return SslType::Alert;
            case 2:
                return SslType::Handshake;
            case 3:
                return SslType::AppData;
            default:
                qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                    index);
                break;
            }
            break;
        }
        case FieldName::HandshakeProtocol:
        {
            switch (index)
            {
            case 0:
                return Handshake::HelloRequest;
            case 1:
                return Handshake::ClientHello;
            case 2:
                return Handshake::ServerHello;
            case 3:
                return Handshake::Certificate;
            case 4:
                return Handshake::ServerKeyExchange;
            case 5:
                return Handshake::CertificateRequest;
            case 6:
                return Handshake::ServerHelloDone;
            case 7:
                return Handshake::CertificateVerify;
            case 8:
                return Handshake::ClientKeyExchange;
            case 9:
                return Handshake::Finished;
            }
            break;
        }
    }
    return -1;
}
