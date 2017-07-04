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

#ifndef _SSL_H
#define _SSL_H

#include "abstractprotocol.h"
#include "ssl.pb.h"

/* 
Ssl Protocol Frame Format -
    +-------+------------+------+
    |  Type |   Version  |  LEN |
    |  (8)  |    (16)    | (16) |
    +-------+------------+------+
Figures in brackets represent field width in bits
*/

class SslProtocol : public AbstractProtocol
{
public:
    enum sslfield
    {
        // Frame Fields
        ssl_type,
        ssl_version,
        ssl_payloadLength,

        ssl_ccs,

        ssl_handshake_type,
        ssl_handshake_length,
        ssl_handshake_version,
        ssl_handshake_random,
        ssl_handshake_sessionIdLen,
        ssl_handshake_sessionId,
        ssl_handshake_ciphersuitesLen,
        ssl_handshake_compMethodsLen,
        ssl_handshake_extensionsLen,
        ssl_handshake_certificatesLen,
        ssl_handshake_keyLen,
        ssl_handshake_key,

        ssl_appData,

        ssl_alert_message,

        ssl_fieldCount
    };

    SslProtocol(StreamBase *stream, AbstractProtocol *parent = 0);
    virtual ~SslProtocol();

    static AbstractProtocol* createInstance(StreamBase *stream,
        AbstractProtocol *parent = 0);
    virtual quint32 protocolNumber() const;

    virtual void protoDataCopyInto(OstProto::Protocol &protocol) const;
    virtual void protoDataCopyFrom(const OstProto::Protocol &protocol);

    virtual ProtocolIdType protocolIdType() const;
    virtual quint32 protocolId(ProtocolIdType type) const;

    virtual QString name() const;
    virtual QString shortName() const;

    virtual int fieldCount() const;
    virtual int frameFieldCount() const;

    virtual AbstractProtocol::FieldFlags fieldFlags(int index) const;
    virtual QVariant fieldData(int index, FieldAttrib attrib,
               int streamIndex = 0) const;
    virtual bool setFieldData(int index, const QVariant &value, 
            FieldAttrib attrib = FieldValue);

    virtual int protocolFrameSize(int streamIndex = 0) const;

    virtual bool isProtocolFrameSizeVariable() const;
    virtual int protocolFrameVariableCount() const;

private:
    OstProto::Ssl    data;
};

#endif
