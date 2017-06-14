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

    sslVersion->setText(
        proto->fieldData(
            SslProtocol::ssl_version,
            AbstractProtocol::FieldValue
        ).toString());

    sslPayloadLength->setText(
        proto->fieldData(
            SslProtocol::ssl_payloadLength,
            AbstractProtocol::FieldValue
        ).toString());


}

/*!
TODO: Edit this function to store each field's data from the config Widget

See AbstractProtocolConfigForm::storeWidget() for more info
*/
void SslConfigForm::storeWidget(AbstractProtocol *proto)
{

    proto->setFieldData(
        SslProtocol::ssl_version,
        sslVersion->text());

    proto->setFieldData(
        SslProtocol::ssl_payloadLength,
        sslPayloadLength->text());


}

