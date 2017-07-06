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

#ifndef _SSL_CONFIG_H
#define _SSL_CONFIG_H

#include "abstractprotocolconfig.h"
#include "ui_ssl.h"

class SslConfigForm : 
    public AbstractProtocolConfigForm, 
    private Ui::Ssl
{
    Q_OBJECT
public:
    SslConfigForm(QWidget *parent = 0);
    virtual ~SslConfigForm();

    enum FieldName {
        SslProtocol,
        HandshakeProtocol
    };

    enum SslType {
        CCS = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        AppData = 0x17
    };

    enum Handshake {
        HelloRequest = 0x00,
        ClientHello = 0x01,
        ServerHello = 0x02,
        Certificate = 0x0b,
        ServerKeyExchange = 0x0c,
        CertificateRequest = 0x0d,
        ServerHelloDone = 0x0e,
        CertificateVerify = 0x0f,
        ClientKeyExchange = 0x10,
        Finished = 0x14
    };

    static SslConfigForm* createInstance();

    virtual void loadWidget(AbstractProtocol *proto);
    virtual void storeWidget(AbstractProtocol *proto);
    int getFieldIndex(int field, QString value);
    int getFieldValue(int field, int index);

};

#endif
