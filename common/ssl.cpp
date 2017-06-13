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

#include "ssl.h"

SslProtocol::SslProtocol(StreamBase *stream, AbstractProtocol *parent)
    : AbstractProtocol(stream, parent)
{
}

SslProtocol::~SslProtocol()
{
}

AbstractProtocol* SslProtocol::createInstance(StreamBase *stream,
    AbstractProtocol *parent)
{
    return new SslProtocol(stream, parent);
}

quint32 SslProtocol::protocolNumber() const
{
    return OstProto::Protocol::kSslFieldNumber;
}

void SslProtocol::protoDataCopyInto(OstProto::Protocol &protocol) const
{
    protocol.MutableExtension(OstProto::ssl)->CopyFrom(data);
    protocol.mutable_protocol_id()->set_id(protocolNumber());
}

void SslProtocol::protoDataCopyFrom(const OstProto::Protocol &protocol)
{
    if (protocol.protocol_id().id() == protocolNumber() &&
            protocol.HasExtension(OstProto::ssl))
        data.MergeFrom(protocol.GetExtension(OstProto::ssl));
}

QString SslProtocol::name() const
{
    return QString("Ssl Protocol");
}

QString SslProtocol::shortName() const
{
    return QString("SSL");
}

/*!
  TODO Return the ProtocolIdType for your protocol \n

  If your protocol doesn't have a protocolId field, you don't need to 
  reimplement this method - the base class implementation will do the 
  right thing
*/

AbstractProtocol::ProtocolIdType SslProtocol::protocolIdType() const
{
    return ProtocolIdIp;
}


/*!
  TODO Return the protocolId for your protoocol based on the 'type' requested \n

  If not all types are valid for your protocol, handle the valid type(s) 
  and for the remaining fallback to the base class implementation; if your 
  protocol doesn't have a protocolId at all, you don't need to reimplement
  this method - the base class will do the right thing
*/

quint32 SslProtocol::protocolId(ProtocolIdType type) const
{
    switch(type)
    {
        case ProtocolIdLlc: return 0xFFFFFF;
        case ProtocolIdEth: return 0xFFFF;
        case ProtocolIdIp: return 0xFF;
        default:break;
    }

    return AbstractProtocol::protocolId(type);
}



int SslProtocol::fieldCount() const
{
    return ssl_fieldCount;
}

/*!
  TODO Return the number of frame fields for your protocol. A frame field
  is a field which has the FrameField flag set \n

  If your protocol has different sets of fields based on a OpCode/Type field
  (e.g. icmp), you MUST re-implement this function; however, if your protocol
  has a fixed set of frame fields always, you don't need to reimplement this 
  method - the base class implementation will do the right thing
*/

int SslProtocol::frameFieldCount() const
{
    return AbstractProtocol::frameFieldCount();
}



/*!
  TODO Edit this function to return the appropriate flags for each field \n

  See AbstractProtocol::FieldFlags for more info
*/
AbstractProtocol::FieldFlags SslProtocol::fieldFlags(int index) const
{
    AbstractProtocol::FieldFlags flags;

    flags = AbstractProtocol::fieldFlags(index);

    switch (index)
    {
        case ssl_type:
        case ssl_version:
        case ssl_payloadLength:
            break;

        case ssl_is_override_checksum:
            flags &= ~FrameField;
            flags |= MetaField;
            break;

        default:
            qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                index);
            break;
    }

    return flags;
}

/*!
TODO: Edit this function to return the data for each field

See AbstractProtocol::fieldData() for more info
*/
QVariant SslProtocol::fieldData(int index, FieldAttrib attrib,
        int streamIndex) const
{
    switch (index)
    {
        case ssl_type:
        {
            int type = data.type() >> 13;

            switch(attrib)
            {
                case FieldName:            
                    return QString("A");
                case FieldValue:
                    return type;
                case FieldTextValue:
                    return QString("%1").arg(type);
                case FieldFrameValue:
                    return QByteArray(1, (char) type);
                case FieldBitSize:
                    return 3;
                default:
                    break;
            }
            break;

        }
        case ssl_version:
        {
            int version = data.version() & 0x1FFF;

            switch(attrib)
            {
                case FieldName:            
                    return QString("B");
                case FieldValue:
                    return version;
                case FieldTextValue:
                    return QString("%1").arg(version, 4, BASE_HEX, QChar('0'));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) version, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 13;
                default:
                    break;
            }
            break;
        }

        case ssl_payloadLength:
        {
            switch(attrib)
            {
                case FieldName:            
                    return QString("Payload Length");
                case FieldValue:
                    return protocolFramePayloadSize(streamIndex);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    int totlen;
                    totlen = protocolFramePayloadSize(streamIndex);
                    fv.resize(2);
                    qToBigEndian((quint16) totlen, (uchar*) fv.data());
                    return fv;
                }
                case FieldTextValue:
                    return QString("%1").arg(
                        protocolFramePayloadSize(streamIndex));
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }
        // Meta fields
        case ssl_is_override_checksum:
        {
            switch(attrib)
            {
                case FieldValue:
                    return data.is_override_checksum();
                default:
                    break;
            }
            break;
        }
        default:
            qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                index);
            break;
    }

    return AbstractProtocol::fieldData(index, attrib, streamIndex);
}

/*!
TODO: Edit this function to set the data for each field

See AbstractProtocol::setFieldData() for more info
*/
bool SslProtocol::setFieldData(int index, const QVariant &value, 
        FieldAttrib attrib)
{
    bool isOk = false;

    if (attrib != FieldValue)
        goto _exit;

    switch (index)
    {
        case ssl_type:
        {
            uint type = value.toUInt(&isOk);
            if (isOk)
                data.set_type((data.type() & 0x1FFF) | ((type & 0x07) << 13));
            break;
        }
        case ssl_version:
        {
            uint version = value.toUInt(&isOk);
            if (isOk)
                data.set_version((data.version() & 0xe000) | (version & 0x1FFF));
            break;
        }
        case ssl_payloadLength:
        {
            uint len = value.toUInt(&isOk);
            if (isOk)
                data.set_payload_length(len);
            break;
        }
        case ssl_is_override_checksum:
        {
            bool ovr = value.toBool();
            data.set_is_override_checksum(ovr);
            isOk = true;
            break;
        }
        default:
            qFatal("%s: unimplemented case %d in switch", __PRETTY_FUNCTION__,
                index);
            break;
    }

_exit:
    return isOk;
}

/*!
  TODO: Return the protocol frame size in bytes\n

  If your protocol has a fixed size - you don't need to reimplement this; the
  base class implementation is good enough
*/
int SslProtocol::protocolFrameSize(int streamIndex) const
{
    return AbstractProtocol::protocolFrameSize(streamIndex);
}

/*!
  TODO: If your protocol frame size can vary across pkts of the same stream,
  return true \n

  Otherwise you don't need to reimplement this method - the base class always
  returns false
*/
bool SslProtocol::isProtocolFrameSizeVariable() const
{
    return false;
}

/*!
  TODO: If your protocol frame has any variable fields or has a variable
  size, return the minimum number of frames required to vary the fields \n

  See AbstractProtocol::protocolFrameVariableCount() for more info
*/
int SslProtocol::protocolFrameVariableCount() const
{
    return AbstractProtocol::protocolFrameVariableCount();
}
