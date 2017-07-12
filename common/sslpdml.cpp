/*
Copyright (C) 2014 Srivats P.

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

#include "sslpdml.h"

#include "ssl.pb.h"

#include <iostream>
#include <QDebug>
#include <QStringList>
/*!
 TODO : Initialize the following inherited protected members -
  - ostProtoId_ 
  - fieldMap_

 ostProtoId_ is the protocol's protobuf field number as defined in
 message 'Protocol' enum 'k' in file protocol.proto

 fieldMap_ is a mapping of the protocol's field names as they appear
 in the PDML to the protobuf field numbers for the protocol. All such
 fields are classified as 'known' fields and the base class will take care
 of decoding these without any help from the subclass. 
 
 Note that the PDML field names are same as the field names used in Wireshark 
 display filters. The full reference for these is available at -
   http://www.wireshark.org/docs/dfref/
*/
PdmlSslProtocol::PdmlSslProtocol()
{
    ostProtoId_ = OstProto::Protocol::kSslFieldNumber;

    fieldMap_.insert("ssl.record.content_type", OstProto::Ssl::kTypeFieldNumber);
    fieldMap_.insert("ssl.record.version", OstProto::Ssl::kVersionFieldNumber);
    fieldMap_.insert("ssl.record.length", OstProto::Ssl::kPayloadLengthFieldNumber);

    fieldMap_.insert("ssl.handshake.cipher_suites_length", OstProto::Ssl::Handshake::kCiphersuitesLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.random", OstProto::Ssl::Handshake::kRandomFieldNumber);
    fieldMap_.insert("ssl.handshake.random_time", OstProto::Ssl::Handshake::kRandomTimeFieldNumber);
    fieldMap_.insert("ssl.handshake.session_id", OstProto::Ssl::Handshake::kSessionIdFieldNumber);
    fieldMap_.insert("ssl.handshake.session_id_length", OstProto::Ssl::Handshake::kSessionIdLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.type", OstProto::Ssl::Handshake::kTypeFieldNumber);
    fieldMap_.insert("ssl.handshake.version", OstProto::Ssl::Handshake::kVersionFieldNumber);
    fieldMap_.insert("ssl.handshake.length", OstProto::Ssl::Handshake::kLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.comp_methods_length", OstProto::Ssl::Handshake::kCompMethodsLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.extensions_length", OstProto::Ssl::Handshake::kExtensionsLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.certificates_length", OstProto::Ssl::Handshake::kCertificatesLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.epms_len", OstProto::Ssl::Handshake::kKeyLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.epms", OstProto::Ssl::Handshake::kKeyFieldNumber);
    fieldMap_.insert("ssl.handshake.cert_types_count", OstProto::Ssl::Handshake::kCertificateTypesCountFieldNumber);
    fieldMap_.insert("ssl.handshake.dnames_len", OstProto::Ssl::Handshake::kDistinguishedNamesLengthFieldNumber);

    // meta
    fieldMap_.insert("ssl.handshake.certificate_length", OstProto::Ssl::Handshake::kCertificateLengthFieldNumber);
    fieldMap_.insert("ssl.handshake.dname_len", OstProto::Ssl::Handshake::kDistinguishedNameLengthFieldNumber);
}

PdmlSslProtocol::~PdmlSslProtocol()
{
}

PdmlProtocol* PdmlSslProtocol::createInstance()
{
    return new PdmlSslProtocol();
}

/*!
 TODO: Use this method to do any special handling that may be required for
 preprocessing a protocol before parsing/decoding the protocol's fields
*/
void PdmlSslProtocol::preProtocolHandler(QString /*name*/, 
        const QXmlStreamAttributes& /*attributes*/, 
        int /*expectedPos*/, OstProto::Protocol* /*pbProto*/,
        OstProto::Stream* /*stream*/)
{
    return;
}

/*!
 TODO: Use this method to do any special handling or cleanup that may be 
 required when a protocol decode is ending prematurely
*/
void PdmlSslProtocol::prematureEndHandler(int /*pos*/, 
        OstProto::Protocol* /*pbProto*/, OstProto::Stream* /*stream*/)
{
    return;
}

/*!
 TODO: Use this method to do any special handling that may be required for
 postprocessing a protocol after parsing/decoding all the protocol fields

 If your protocol's protobuf has some meta-fields that should be set to
 their non default values, this is a good place to do that. e.g. derived
 fields such as length, checksum etc. may be correct or incorrect in the
 PCAP/PDML - to retain the same value as in the PCAP/PDML and not let
 Ostinato recalculate these, you can set the is_override_length,
 is_override_cksum meta-fields to true here
*/
void PdmlSslProtocol::postProtocolHandler(OstProto::Protocol* /*pbProto*/,
        OstProto::Stream* /*stream*/)
{
    return;
}

void PdmlSslProtocol::knownFieldHandler(QString name, QString valueHexStr,
        const QXmlStreamAttributes& attributes, OstProto::Protocol *pbProto)
{
    if(name.split('.')[1]=="handshake")
    {
        handshakeHandler(name, valueHexStr, attributes, pbProto);
    }

    else
    {
        QString showname;
        showname.append(attributes.value("showname"));
        const google::protobuf::Reflection *protoRefl = pbProto->GetReflection();

        const google::protobuf::FieldDescriptor *extDesc =
                    protoRefl->FindKnownExtensionByNumber(ostProtoId());

        google::protobuf::Message *msg =
                    protoRefl->MutableMessage(pbProto,extDesc);

        const google::protobuf::Reflection *msgRefl = msg->GetReflection();

        const google::protobuf::FieldDescriptor *fieldDesc =
                    msg->GetDescriptor()->FindFieldByNumber(fieldId(name));

        const google::protobuf::FieldDescriptor *fieldDescShowName =
                    msg->GetDescriptor()->FindFieldByNumber(fieldId(name) + 1);


        bool isOk;

        Q_ASSERT(fieldDesc != NULL);

        switch(fieldDesc->cpp_type())
        {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            msgRefl->SetBool(msg, fieldDesc, bool(valueHexStr.toUInt(&isOk)));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: // TODO
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
            msgRefl->SetUInt32(msg, fieldDesc,
                    valueHexStr.toUInt(&isOk, kBaseHex));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
            msgRefl->SetUInt64(msg, fieldDesc,
                    valueHexStr.toULongLong(&isOk, kBaseHex));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
        {
            QByteArray hexVal = QByteArray::fromHex(valueHexStr.toUtf8());
            std::string str(hexVal.constData(), hexVal.size());
            msgRefl->SetString(msg, fieldDesc, str);
            break;
        }
        default:
            qFatal("%s: unhandled cpptype = %d", __FUNCTION__,
                    fieldDesc->cpp_type());
        }

        QByteArray hexVal = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
        std::string str(hexVal.constData(), hexVal.size());
        msgRefl->SetString(msg, fieldDescShowName, str);
    }

}

/*!
 TODO: Handle all 'unknown' fields using this method

 You need to typically only handle frame fields or fields actually present
 in the protocol on the wire. So you can safely ignore meta-fields such as
 Good/Bad Checksum.

 Some fields may not have a 'name' attribute, so cannot be classified as
 a 'known' field. Use this method to identify such fields using other
 attributes such as 'show' or 'showname' and populate the corresponding
 protobuf field.

 If the PDML protocol contains some fields that are not supported by Ostinato,
 use a HexDump protocol as a replacement to store these bytes
*/
void PdmlSslProtocol::unknownFieldHandler(QString name,
        int /*pos*/, int /*size*/, const QXmlStreamAttributes& attributes,
        OstProto::Protocol* pbProto, OstProto::Stream* /*stream*/)
{
    std::string  strShowName;
    OstProto::Ssl *ssl = pbProto->MutableExtension(OstProto::ssl);
    bool isOk;

    if(!attributes.value("showname").isEmpty())
    {
        QString showname;
        showname.append(attributes.value("showname"));
        QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
        strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());
    }

    if(name=="ssl.change_cipher_spec")
    {
        OstProto::Ssl::ChangeCipherSpec  *ccs = ssl->mutable_change_cipher_spec();
        ccs->set_ccs(1);
        ccs->set_ccs_showname(strShowName);
    }

    else if(name=="ssl.handshake")
    {
        ssl->set_handshake_showname(strShowName);
    }

    else if(name=="ssl.app_data")
    {
        OstProto::Ssl::ApplicationData *data = ssl->mutable_app_data();
        QByteArray dataArray = QByteArray::fromHex(attributes.value("value").toLatin1());
        std::string strData(dataArray.constData(), dataArray.size());
        data->set_data(strData);
        data->set_data_showname(strShowName);
    }

    else if(name=="ssl.alert_message")
    {
        OstProto::Ssl::Alert *alert = ssl->mutable_alert();
        alert->set_alert_message(attributes.value("value").toString().toInt(&isOk, kBaseHex));
        alert->set_alert_message_showname(strShowName);
    }

    else if(name=="ssl.handshake.ciphersuite")
    {
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        handshake->add_ciphersuite(attributes.value("value").toString().toInt(&isOk, kBaseHex));
        handshake->add_ciphersuite_showname(strShowName);
    }

    else if(name=="ssl.handshake.comp_method")
    {
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        handshake->add_comp_method(attributes.value("value").toString().toInt(&isOk, kBaseHex));
        handshake->add_comp_method_showname(strShowName);
    }

    else if(name=="" && attributes.value("show").toString().startsWith("Extension"))
    {
        QString showname;
        showname.append(attributes.value("show"));
        QByteArray byteArrayShowName = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
        strShowName = std::string(byteArrayShowName.constData(), byteArrayShowName.size());

        QByteArray dataArray = QByteArray::fromHex(attributes.value("value").toLatin1());
        std::string strData(dataArray.constData(), dataArray.size());

        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        handshake->add_extension(strData);
        handshake->add_extension_showname(strShowName);
    }

    else if(name=="ssl.handshake.certificate")
    {
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        QByteArray dataArray;
        dataArray.append(QString().fromStdString(handshake->certificate_length()));
        dataArray.append(QByteArray::fromHex(attributes.value("value").toLatin1()));
        std::string strData(dataArray.constData(), dataArray.size());
        handshake->add_certificate(strData);
        handshake->add_certificate_showname(strShowName);
    }

    else if(name=="ssl.handshake.cert_type")
    {
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        handshake->add_certificate_type(attributes.value("value").toString().toInt(&isOk, kBaseHex));
        handshake->add_certificate_type_showname(strShowName);
    }

    else if(name=="ssl.handshake.dname")
    {
        // x509if.RDNSequence_item
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        QByteArray dataArray;
        dataArray.append(QString().fromStdString(handshake->distinguished_name_length()));
        std::string strData(dataArray.constData(), dataArray.size());
        handshake->add_distinguished_name(strData);
        handshake->add_distinguished_name_showname(strShowName);
    }

    else if(name=="x509if.RDNSequence_item")
    {
        OstProto::Ssl::Handshake *handshake = ssl->mutable_handshake();
        if(handshake->distinguished_name_size())
        {
            QByteArray dataArray;
            dataArray.append(QString().fromStdString(handshake->distinguished_name(handshake->distinguished_name_size() - 1)));
            dataArray.append(QByteArray::fromHex(attributes.value("value").toLatin1()));
            std::string strData(dataArray.constData(), dataArray.size());
            handshake->set_distinguished_name(handshake->distinguished_name_size() - 1, strData);
        }
    }

    return;
}

void PdmlSslProtocol::handshakeHandler(QString name, QString valueHexStr,
        const QXmlStreamAttributes &attributes, OstProto::Protocol *pbProto)
{
    QString showname;
    showname.append(attributes.value("showname"));
    bool isOk;
    OstProto::Ssl *ssl = pbProto->MutableExtension(OstProto::ssl);

    OstProto::Ssl::Handshake *msg = ssl->mutable_handshake();

    const google::protobuf::Reflection *msgRefl = msg->GetReflection();

    const google::protobuf::FieldDescriptor *fieldDesc =
                msg->GetDescriptor()->FindFieldByNumber(fieldId(name));

    const google::protobuf::FieldDescriptor *fieldDescShowName =
                msg->GetDescriptor()->FindFieldByNumber(fieldId(name) + 1);

    Q_ASSERT(fieldDesc != NULL);
    switch(fieldDesc->cpp_type())
    {
        case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
            msgRefl->SetBool(msg, fieldDesc, bool(valueHexStr.toUInt(&isOk)));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: // TODO
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
            msgRefl->SetUInt32(msg, fieldDesc,
                    valueHexStr.toUInt(&isOk, kBaseHex));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
            msgRefl->SetUInt64(msg, fieldDesc,
                    valueHexStr.toULongLong(&isOk, kBaseHex));
            break;
        case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
        {
            QByteArray hexVal = QByteArray::fromHex(valueHexStr.toUtf8());
            std::string str(hexVal.constData(), hexVal.size());
            msgRefl->SetString(msg, fieldDesc, str);
            break;
        }
        default:
            qDebug("%s: unhandled cpptype = %d", __FUNCTION__,
                    fieldDesc->cpp_type());
    }
    QByteArray hexVal = QByteArray::fromRawData(showname.toUtf8(), showname.toUtf8().size());
    std::string str(hexVal.constData(), hexVal.size());
    msgRefl->SetString(msg, fieldDescShowName, str);
    return;
}
