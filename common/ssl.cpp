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
#include <iostream>
#include <QDebug>
#include <QStringList>

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
    QString name;
    switch (data.type()) {
    case 0x14:
        name.append("Change Cipher Spec");
        break;
    case 0x15:
        name.append("Alert");
        break;
    case 0x16:
        name.append((QString::fromUtf8(data.handshake().type_showname().c_str())).split('(')[0]);
        break;
    case 0x17:
        name.append("Application Data");
        break;
    default:
        break;
    }
    return QString("SSL Protocol: ").append(name);
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

        case ssl_ccs:
            if(!data.has_change_cipher_spec())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
            break;
        case ssl_handshake_type:
            if(!data.has_handshake() || !data.handshake().has_type())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
            break;
        case ssl_handshake_length:
            if(!data.has_handshake() || !data.handshake().has_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;

        case ssl_handshake_version:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().has_version())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;

        case ssl_handshake_random:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !(data.handshake().has_random() || data.handshake().has_random_time()))
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_sessionIdLen:
            if(!data.has_handshake()|| !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().has_session_id_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_sessionId:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().has_session_id())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_ciphersuitesLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01) || !data.handshake().has_ciphersuites_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_compMethodsLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01) || !data.handshake().has_comp_methods_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_extensionsLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().has_extensions_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_certificatesLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x0b) || !data.handshake().has_certificates_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_keyLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x10 || data.handshake().type() == 0x0c) || !data.handshake().has_key_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_key:
            if(!data.has_handshake() || !(data.handshake().type() == 0x10 || data.handshake().type() == 0x0c) || !data.handshake().has_key())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_ciphersuite:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().ciphersuite_size())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_compMethod:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().comp_method_size())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_extension:
            if(!data.has_handshake() || !(data.handshake().type() == 0x01 || data.handshake().type() == 0x02) || !data.handshake().extension_size())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_appData:
            if(!data.has_app_data() || !data.app_data().has_data())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_alert_message:
        if(!data.has_alert() || !data.alert().has_alert_message())
        {
            flags &= ~FrameField;
            flags |= MetaField;
        }
        break;
        case ssl_handshake_certificate:
        if(!data.has_handshake() || !(data.handshake().type() == 0x10) || !data.handshake().certificate_size())
        {
            flags &= ~FrameField;
            flags |= MetaField;
        }
        break;
        case ssl_handshake_certificateTypesCount:
            if(!data.has_handshake() || !(data.handshake().type() == 0x0d) || !data.handshake().has_certificate_types_count())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_distinguishedNamesLen:
            if(!data.has_handshake() || !(data.handshake().type() == 0x0d) || !data.handshake().has_distinguished_names_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_certificateType:
            if(!data.has_handshake() || !(data.handshake().type() == 0x0d) || !data.handshake().certificate_type_size())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_distinguishedName:
        if(!data.has_handshake() || !(data.handshake().type() == 0x0d) || !data.handshake().distinguished_name_size())
        {
            flags &= ~FrameField;
            flags |= MetaField;
        }
        break;
        case ssl_handshake_signatureLen:
            if(!data.has_handshake()|| !(data.handshake().type() == 0x0f) || !data.handshake().has_signature_length())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
        break;
        case ssl_handshake_signature:
            if(!data.has_handshake()|| !(data.handshake().type() == 0x0f) || !data.handshake().has_signature())
            {
                flags &= ~FrameField;
                flags |= MetaField;
            }
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
            int type = data.type() & 0xFF;
            switch(attrib)
            {
                case FieldName:
                    return QString("Content Type");
                case FieldValue:
                    return QString("%1").arg(type, 2, BASE_HEX, QChar('0'));
                case FieldTextValue:
                    return QString("%1 (%2)").arg(type, 4, BASE_HEX, QChar('0')).arg(QString::fromUtf8(data.type_showname().c_str()));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) type, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;

        }
        case ssl_version:
        {
            int version = data.version() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Version");
                case FieldValue:
                    return QString("%1").arg(version, 4, BASE_HEX, QChar('0'));
                case FieldTextValue:
                    return QString("%1 (%2)").arg(version, 4, BASE_HEX, QChar('0')).arg(QString::fromUtf8(data.version_showname().c_str()));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) version, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_payloadLength:
        {
            int payload_length = data.payload_length() & 0xFFFF;
            switch(attrib)
            {
                case FieldName:
                    return QString("Length");
                case FieldValue:
                    return payload_length;
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) payload_length, (uchar*) fv.data());
                    return fv;
                }
                case FieldTextValue:
                    return QString("%1").arg(payload_length);
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }


        case ssl_ccs:
        {
            int ccs = data.change_cipher_spec().ccs() & 0xFF;
            switch(attrib)
            {
                case FieldName:
                    return QString("Change Cipher Spec");
                case FieldValue:
                    return ccs;
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) ccs, (uchar*) fv.data());
                    return fv;
                }
                case FieldTextValue:
                    return QString("%1").arg(ccs, 2, BASE_HEX, QChar('0'));
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_type:
        {
            int type = data.handshake().type() & 0xFF;
            switch(attrib)
            {
                case FieldName:
                    return QString("Handshake Type");
                case FieldValue:
                return QString("%1").arg(type, 2, BASE_HEX, QChar('0'));
                case FieldTextValue:
                    return QString("%1 (%2)").arg(type, 2, BASE_HEX, QChar('0')).arg(QString::fromUtf8(data.handshake().type_showname().c_str()));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) type, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_length:
        {
            int length = data.handshake().length() & 0xFFFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Handshake Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(3);
                    // Set 24 bits! Don't use <<
                    qToBigEndian((quint32) length<<8, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 24;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_version  :
        {
            int version = data.handshake().version() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Handshake Version");
                case FieldValue:
                    return QString("%1").arg(version, 4, BASE_HEX, QChar('0'));
                case FieldTextValue:
                    return QString("%1 (%2)").arg(version, 4, BASE_HEX, QChar('0')).arg(QString::fromUtf8(data.handshake().version_showname().c_str()));
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) version, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_random:
        {
            QByteArray random;
            random.append(QString().fromStdString(data.handshake().random_time()));
            random.append(QString().fromStdString(data.handshake().random()));
            switch (attrib) {
            case FieldName:
                return QString("Random");
            case FieldValue:
                return random.toHex();
            case FieldTextValue:
                return QString::fromStdString(data.handshake().random_time_showname()).append(QString("\n")).append(QString::fromStdString(data.handshake().random_showname()));
            case FieldFrameValue:
                return random;
            default:
                break;
            }
            break;
        }

        case ssl_handshake_sessionIdLen:
        {
            int length = data.handshake().session_id_length() & 0xFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Session ID Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_sessionId:
        {
            QByteArray sessionId;
            sessionId.append(QString().fromStdString(data.handshake().session_id()));
            switch (attrib) {
            case FieldName:
                return QString("Session ID");
            case FieldValue:
                return sessionId.toHex();
            case FieldTextValue:
                return sessionId.toHex();
            case FieldFrameValue:
                return sessionId;
            default:
                break;
            }
            break;
        }

        case ssl_handshake_ciphersuitesLen:
        {
            int length = data.handshake().ciphersuites_length() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Ciphersuites Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_compMethodsLen:
        {
            int length = data.handshake().comp_methods_length() & 0xFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Compression Methods Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_extensionsLen:
        {
            int length = data.handshake().extensions_length() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Extensions Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_certificatesLen:
        {
            int length = data.handshake().certificates_length() & 0xFFFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Certificates Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(3);
                    qToBigEndian((quint32) length<<8, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 24;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_keyLen:
        {
            int length = data.handshake().key_length() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Key Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_key:
        {
            QByteArray key;
            key.append(QString().fromStdString(data.handshake().key()));
            switch (attrib) {
            case FieldName:
                return QString("Key");
            case FieldValue:
                return key.toHex();
            case FieldTextValue:
                return key.toHex();
            case FieldFrameValue:
                return key;
            default:
                break;
            }
            break;
        }

        case ssl_handshake_ciphersuite :
        {
            switch(attrib)
            {
                case FieldName:
                    return QString("Cipher Suites");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().ciphersuite_size(); i++)
                    {
                        list.append(QString("%1").arg(data.handshake().ciphersuite(i), 4, BASE_HEX, QChar('0')));
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().ciphersuite_showname_size(); i++)
                    {
                        list.append("\n   ");
                        // hex value of ciphersuite is removed using a bad method (split) fix this when possible
                        list.append(QString::fromUtf8(data.handshake().ciphersuite_showname(i).c_str()).split('(')[0]);
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().ciphersuite_size(); i++)
                    {
                        int ciphersuite = data.handshake().ciphersuite(i) & 0xFFFF;
                        QByteArray rv;
                        rv.resize(2);
                        qToBigEndian((quint16) ciphersuite, (uchar*) rv.data());
                        fv.append(rv);
                    }
                    return fv;
                }
                case FieldBitSize:
                    return data.handshake().ciphersuite_size() * 2 * 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_compMethod:
        {
            switch(attrib)
            {
                case FieldName:
                    return QString("Compression Methods");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().comp_method_size(); i++)
                    {
                        list.append(QString("%1").arg(data.handshake().comp_method(i), 2, BASE_HEX, QChar('0')));
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().comp_method_showname_size(); i++)
                    {
                        list.append("\n   ");
                        list.append(QString::fromUtf8(data.handshake().comp_method_showname(i).c_str()));
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().comp_method_size(); i++)
                    {
                        int compMethod = data.handshake().comp_method(i) & 0xFF;
                        QByteArray rv;
                        rv.resize(1);
                        qToBigEndian((quint8) compMethod, (uchar*) rv.data());
                        fv.append(rv);
                    }
                    return fv;
                }
                case FieldBitSize:
                    return data.handshake().comp_method_size() * 8;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_extension:
        {
            switch (attrib) {
                case FieldName:
                    return QString("Extentions: ");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().extension_size(); i++)
                    {
                        QByteArray item;
                        item.append(QString().fromStdString(data.handshake().extension(i)));
                        list.append(item.toHex());
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().extension_showname_size(); i++)
                    {
                        const char *tmp = data.handshake().extension_showname(i).c_str();
                        if(strlen(tmp)) {
                            list.append("\n   ");
                            list.append(tmp);
                        }
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().extension_size(); i++)
                    {
                        fv.append(QString().fromStdString(data.handshake().extension(i)));
                    }
                    return fv;
                }
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_certificate:
        {
            switch (attrib) {
                case FieldName:
                    return QString("Certificates");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().certificate_size(); i++)
                    {
                        QByteArray item;
                        item.append(QString().fromStdString(data.handshake().certificate(i)));
                        list.append(item.toHex());
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().certificate_size(); i++)
                    {
                        list.append("\n   ");
                        list.append(data.handshake().certificate_showname(i).c_str());
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().certificate_size(); i++)
                    {
                        fv.append(QString().fromStdString(data.handshake().certificate(i)));
                    }
                    return fv;
                }
                default:
                    break;
            }
            break;
        }

        case ssl_appData:
        {
            QByteArray appData;
            appData.append(QString().fromStdString(data.app_data().data()));
            switch (attrib) {
            case FieldName:
                return QString("Application Data");
            case FieldValue:
                return appData.toHex();
            case FieldTextValue:
                return appData.toHex();
            case FieldFrameValue:
                return appData;
            default:
                break;
            }
            break;
        }

        case ssl_alert_message:
        {
            int alert = data.alert().alert_message();
            switch (attrib) {
            case FieldName:
                return QString("Alert");
            case FieldValue:
                return QString("%1").arg(alert, 4, BASE_HEX, QChar('0'));
            case FieldTextValue:
                return QString("%1 (%2)").arg(alert, 4, BASE_HEX, QChar('0')).arg(QString::fromUtf8(data.alert().alert_message_showname().c_str()));
            case FieldFrameValue:
            {
                QByteArray fv;
                fv.resize(2);
                qToBigEndian((quint16) alert, (uchar*) fv.data());
                return fv;
            }
            case FieldBitSize:
                return 16;
            default:
                break;
            }
            break;
        }

        case ssl_handshake_certificateTypesCount:
        {
            int count = data.handshake().certificate_types_count() & 0xFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Certificate Types Count");
                case FieldValue:
                    return count;
                case FieldTextValue:
                    return QString("%1").arg(count);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(1);
                    qToBigEndian((quint8) count, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 8;
                default:
                    break;
            }
            break;
        }


        case ssl_handshake_distinguishedNamesLen:
        {
            int length = data.handshake().distinguished_names_length() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Distinguished Names Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_certificateType:
        {
            switch(attrib)
            {
                case FieldName:
                    return QString("Certificate Type");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().certificate_type_size(); i++)
                    {
                        list.append(QString("%1").arg(data.handshake().certificate_type(i), 4, BASE_HEX, QChar('0')));
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().certificate_type_showname_size(); i++)
                    {
                        list.append("\n   ");
                        list.append(QString::fromUtf8(data.handshake().certificate_type_showname(i).c_str()));
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().certificate_type_size(); i++)
                    {
                        int certType = data.handshake().certificate_type(i) & 0xFF;
                        QByteArray rv;
                        rv.resize(1);
                        qToBigEndian((quint8) certType, (uchar*) rv.data());
                        fv.append(rv);
                    }
                    return fv;
                }
                case FieldBitSize:
                    return data.handshake().certificate_type_size() * 8;
                default:
                    break;
            }
            break;
        }


        case ssl_handshake_distinguishedName:
        {
            switch (attrib) {
                case FieldName:
                    return QString("Distinguished Names");
                case FieldValue:
                {
                    QStringList list;
                    for (int i=0; i < data.handshake().distinguished_name_size(); i++)
                    {
                        QByteArray item;
                        item.append(QString().fromStdString(data.handshake().distinguished_name(i)));
                        list.append(item.toHex());
                    }
                    return list;
                }
                case FieldTextValue:
                {
                    QString list;
                    for (int i=0; i < data.handshake().distinguished_name_showname_size(); i++)
                    {
                        list.append("\n   ");
                        list.append(data.handshake().distinguished_name_showname(i).c_str());
                    }
                    return list;
                }
                case FieldFrameValue:
                {
                    QByteArray fv;
                    for (int i=0; i < data.handshake().distinguished_name_size(); i++)
                    {
                        fv.append(QString().fromStdString(data.handshake().distinguished_name(i)));
                    }
                    return fv;
                }
                default:
                    break;
            }
            break;
        }

        case ssl_handshake_signatureLen:
        {
            int length = data.handshake().signature_length() & 0xFFFF;

            switch(attrib)
            {
                case FieldName:
                    return QString("Signature Length");
                case FieldValue:
                    return length;
                case FieldTextValue:
                    return QString("%1").arg(length);
                case FieldFrameValue:
                {
                    QByteArray fv;
                    fv.resize(2);
                    qToBigEndian((quint16) length, (uchar*) fv.data());
                    return fv;
                }
                case FieldBitSize:
                    return 16;
                default:
                    break;
            }
            break;
        }
        case ssl_handshake_signature:
        {
            QByteArray signature;
            signature.append(QString().fromStdString(data.handshake().signature()));
            switch (attrib) {
            case FieldName:
                return QString("Signature");
            case FieldValue:
                return signature.toHex();
            case FieldTextValue:
                return signature.toHex();
            case FieldFrameValue:
                return signature;
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
                data.set_type(type);

            QString showname = getName(sslType, type).toString();
            QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
            std::string strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());
            data.set_type_showname(strShowName);

            if(type != 0x14)
                data.clear_change_cipher_spec();
            if(type != 0x15)
                data.clear_alert();
            if(type != 0x16)
                data.clear_handshake();
            if(type != 0x17)
                data.clear_app_data();

            break;
        }
        case ssl_version:
        {
            uint version = value.toUInt(&isOk);
            if (isOk)
                data.set_version(version);

            QString showname = getName(SslProtocol::version, version).toString();
            QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
            std::string strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());
            data.set_version_showname(strShowName);

            break;
        }
        case ssl_payloadLength:
        {
            uint len = value.toUInt(&isOk);
            if (isOk)
                data.set_payload_length(len);
            break;
        }
        case ssl_alert_message:
        {
            uint alert = value.toInt(&isOk);
            if(isOk)
                data.mutable_alert()->set_alert_message(alert);
            break;
        }
        case ssl_ccs:
        {
            data.mutable_change_cipher_spec()->set_ccs(1);
            break;
        }
        case ssl_handshake_type:
        {
            uint type = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_type(type);

            QString showname = getName(handshakeType, type).toString();
            QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
            std::string strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());
            data.mutable_handshake()->set_type_showname(strShowName);

            break;
        }
        case ssl_handshake_length:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_length(length);
            break;
        }
        case ssl_handshake_version:
        {
            uint version = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_version(version);

            QString showname = getName(SslProtocol::version, version).toString();
            QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
            std::string strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());
            data.mutable_handshake()->set_version_showname(strShowName);

            break;
        }
        case ssl_handshake_random:
        {
            QByteArray timeArray = QByteArray::fromHex(value.toString().left(8).toLatin1());
            std::string strTime(timeArray.constData(), timeArray.size());
            data.mutable_handshake()->set_random_time(strTime);

            QByteArray bytesArray = QByteArray::fromHex(value.toString().right(56).toLatin1());
            std::string strBytes(bytesArray.constData(), bytesArray.size());
            data.mutable_handshake()->set_random(strBytes);

            break;
        }
        case ssl_handshake_sessionIdLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_session_id_length(length);
            break;
        }
        case ssl_handshake_sessionId:
        {
            QByteArray idArray = QByteArray::fromHex(value.toString().toLatin1());
            std::string strId(idArray.constData(), idArray.size());
            data.mutable_handshake()->set_session_id(strId);
            break;
        }
        case ssl_handshake_ciphersuitesLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_ciphersuites_length(length);
            break;
        }
        case ssl_handshake_compMethodsLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_comp_methods_length(length);
            break;
        }
        case ssl_handshake_extensionsLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_extensions_length(length);
            break;
        }
        case ssl_handshake_certificatesLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_certificates_length(length);
            break;
        }
        case ssl_handshake_ciphersuite:
        {
            data.mutable_handshake()->clear_ciphersuite();
            if(data.handshake().type()==0x02) {
                data.mutable_handshake()->clear_ciphersuite_showname();
                data.mutable_handshake()->add_ciphersuite_showname(QString("Unknown").toStdString());
            }
            bool isOk;
            QStringList list = value.toStringList();
            for  (int i=0; i < list.size(); i++)
            {
                uint val = list.at(i).toInt(&isOk, 16);
                if (isOk) {
                    data.mutable_handshake()->add_ciphersuite(val & 0xFFFF);
                }
            }
            break;
        }
        case ssl_handshake_compMethod:
        {
            data.mutable_handshake()->clear_comp_method();
            bool isOk;
            QStringList list = value.toStringList();
            for  (int i=0; i < list.size(); i++)
            {
                uint val = list.at(i).toInt(&isOk, 16);
                if (isOk)
                    data.mutable_handshake()->add_comp_method(val & 0xFF);
            }
            break;
        }

        case ssl_handshake_extension:
        {
            data.mutable_handshake()->clear_extension();
            QStringList list = value.toStringList();

            for (int i = 0; i < list.size(); i++)
            {
                QByteArray itemArray = QByteArray::fromHex(list.at(i).toLatin1());
                std::string strItem(itemArray.constData(), itemArray.size());
                data.mutable_handshake()->add_extension(strItem);
            }
            break;
        }

        case ssl_handshake_certificate:
        {
            data.mutable_handshake()->clear_certificate();
            QStringList list = value.toStringList();
            for (int i = 0; i < list.size(); i++)
            {
                QByteArray itemArray = QByteArray::fromHex(list.at(i).toLatin1());
                std::string strItem(itemArray.constData(), itemArray.size());
                data.mutable_handshake()->add_certificate(strItem);
            }
            break;
        }

        case ssl_handshake_keyLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_key_length(length);
            break;
        }

        case ssl_handshake_key:
        {
            QByteArray dataArray = QByteArray::fromHex(value.toString().toLatin1());
            std::string strData(dataArray.constData(), dataArray.size());
            data.mutable_handshake()->set_key(strData);
            break;
        }

        case ssl_appData:
        {
            QByteArray dataArray = QByteArray::fromHex(value.toString().toLatin1());
            std::string strData(dataArray.constData(), dataArray.size());
            data.mutable_app_data()->set_data(strData);
            break;
        }

        case ssl_handshake_certificateTypesCount:
        {
            uint count = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_certificate_types_count(count);
            break;
        }

        case ssl_handshake_distinguishedNamesLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_distinguished_names_length(length);
            break;
        }
        case ssl_handshake_certificateType:
        {
            data.mutable_handshake()->clear_certificate_type();
            bool isOk;
            QStringList list = value.toStringList();
            for  (int i=0; i < list.size(); i++)
            {
                uint val = list.at(i).toInt(&isOk, 16);
                if (isOk)
                    data.mutable_handshake()->add_certificate_type(val & 0xFF);
            }
            break;
        }

        case ssl_handshake_distinguishedName:
        {
            data.mutable_handshake()->clear_distinguished_name();
            QStringList list = value.toStringList();
            for (int i = 0; i < list.size(); i++)
            {
                QByteArray itemArray = QByteArray::fromHex(list.at(i).toLatin1());
                std::string strItem(itemArray.constData(), itemArray.size());
                data.mutable_handshake()->add_distinguished_name(strItem);
            }
            break;
        }

        case ssl_handshake_signatureLen:
        {
            uint length = value.toInt(&isOk);
            if(isOk)
                data.mutable_handshake()->set_signature_length(length);
            break;
        }
        case ssl_handshake_signature:
        {
            QByteArray dataArray = QByteArray::fromHex(value.toString().toLatin1());
            std::string strData(dataArray.constData(), dataArray.size());
            data.mutable_handshake()->set_signature(strData);
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

/*
    Show names!
*/

QVariant SslProtocol::getName(int type, QVariant value)
{
    bool isOk;

    switch (type)
    {
    case version:
    {
        int index = value.toInt(&isOk);
        if(!isOk)
            return QString("Invalid");
        switch (index)
        {
            case 0x0300:
                return QString("SSL 3.0");
            case 0x0301:
                return QString("TLS 1.0");
            case 0x0302:
                return QString("TLS 1.1");
            case 0x0303:
                return QString("TLS 1.2");
            default:
                return QString("Invalid");
        }
    }
    case sslType:
    {
        int index = value.toInt(&isOk);
        if(!isOk)
            return QString("Invalid");
        switch (index) {
        case 0x14:
            return QString("Change Cipher Spec");
        case 0x15:
            return QString("Alert");
        case 0x16:
            return QString("Handshake");
        case 0x17:
            return QString("Application Data");
        default:
            return QString("Invalid");
        }
    }
    case handshakeType:
    {
        int index = value.toInt(&isOk);
        if(!isOk)
            return QString("Invalid");
        switch (index)
        {
        case 0x00:
            return QString("Hello Request");
        case 0x01:
            return QString("Client Hello");
        case 0x02:
            return QString("Server Hello");
        case 0x0b:
            return QString("Certificate");
        case 0x0c:
            return QString("Server Key Exchange");
        case 0x0d:
            return QString("Certificate Request");
        case 0x0e:
            return QString("Server Hello Done");
        case 0x0f:
            return QString("Certificate Verify");
        case 0x10:
            return QString("Client Key Exchange");
        case 0x14:
            return QString("Finished");
        default:
            return QString("Invalid");
        }
    }
    default:
        return QString("Invalid");
    }
}
