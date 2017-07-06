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
        getProtocolIndex(
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
}

/*!
TODO: Edit this function to store each field's data from the config Widget

See AbstractProtocolConfigForm::storeWidget() for more info
*/
void SslConfigForm::storeWidget(AbstractProtocol *proto)
{
    bool isOk;
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

    proto->setFieldData(
        SslProtocol::ssl_type,
        getProtocolValue(cbSslType->currentIndex()));
}

int SslConfigForm::getProtocolIndex(QString value)
{
    bool isOk;
    int index = value.toInt(&isOk, 16);
    switch (index) {
    case 0x14:
        return 0;
    case 0x15:
        return 1;
    case 0x16:
        return 2;
    case 0x17:
        return 3;
    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
            index);
        break;
    }
    return -1;
}

int SslConfigForm::getProtocolValue(int index)
{
    switch (index) {
    case 0:
        return 0x14;
    case 1:
        return 0x15;
    case 2:
        return 0x16;
    case 3:
        return 0x17;
    default:
        qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
            index);
        break;
    }
    return -1;
}
