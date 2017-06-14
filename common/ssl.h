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

        // Meta Fields
        ssl_is_override_checksum,


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
