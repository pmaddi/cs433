/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/ls-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("LSMessage");
NS_OBJECT_ENSURE_REGISTERED (LSMessage);

LSMessage::LSMessage ()
{
}

LSMessage::~LSMessage ()
{
}

LSMessage::LSMessage (LSMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId
LSMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("LSMessage")
    .SetParent<Header> ()
    .AddConstructor<LSMessage> ()
  ;
  return tid;
}

TypeId
LSMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
LSMessage::GetSerializedSize (void) const
{
  // size of messageType, sequence number, originator address, ttl
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t) + IPV4_ADDRESS_SIZE + sizeof (uint8_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;
      case HELLO:
        size += m_message.hello.GetSerializedSize();
        break;
      case HELLO_RSP:
        size += m_message.helloRsp.GetSerializedSize();
        break;
      case LS_UPDATE:
        size += m_message.lsUpdate.GetSerializedSize();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
LSMessage::Print (std::ostream &os) const
{
  os << "\n****LSMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "sequenceNumber: " << m_sequenceNumber << "\n";
  os << "ttl: " << m_ttl << "\n";
  os << "originatorAddress: " << m_originatorAddress << "\n";
  os << "PAYLOAD:: \n";

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
        break;
      case HELLO:
        m_message.hello.Print (os);
        break;
      case HELLO_RSP:
        m_message.helloRsp.Print (os);
        break;
      case LS_UPDATE:
        m_message.lsUpdate.Print (os);
        break;
      default:
        break;
    }
  os << "\n****END OF MESSAGE****\n";
}

void
LSMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_sequenceNumber);
  i.WriteU8 (m_ttl);
  i.WriteHtonU32 (m_originatorAddress.Get ());

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
        break;
      case HELLO:
        m_message.hello.Serialize(i);
        break;
      case HELLO_RSP:
        m_message.helloRsp.Serialize(i);
        break;
      case LS_UPDATE:
        m_message.lsUpdate.Serialize(i);
        break;
      default:
        NS_ASSERT (false);
    }
}

uint32_t
LSMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_sequenceNumber = i.ReadNtohU32 ();
  m_ttl = i.ReadU8 ();
  m_originatorAddress = Ipv4Address (i.ReadNtohU32 ());

  size = sizeof (uint8_t) + sizeof (uint32_t) + sizeof (uint8_t) + IPV4_ADDRESS_SIZE;

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
        break;
      case HELLO:
        m_message.hello.Deserialize(i);
        break;
      case HELLO_RSP:
        m_message.helloRsp.Deserialize(i);
        break;
      case LS_UPDATE:
        m_message.lsUpdate.Deserialize(i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t
LSMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
LSMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
LSMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
LSMessage::PingReq::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
LSMessage::SetPingReq (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.destinationAddress = destinationAddress;
  m_message.pingReq.pingMessage = pingMessage;
}

LSMessage::PingReq
LSMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t
LSMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
LSMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
LSMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
LSMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
LSMessage::SetPingRsp (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.destinationAddress = destinationAddress;
  m_message.pingRsp.pingMessage = pingMessage;
}

LSMessage::PingRsp
LSMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


// Hello

uint32_t
LSMessage::Hello::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + msg.length();
  return size;
}

void
LSMessage::Hello::Print (std::ostream &os) const
{
  os << "Hello:: Message: " << msg << "\n";
}

void
LSMessage::Hello::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (msg.length ());
  start.Write ((uint8_t *) (const_cast<char*> (msg.c_str())), msg.length());
}

uint32_t
LSMessage::Hello::Deserialize (Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  msg = std::string (str, length);
  return Hello::GetSerializedSize ();
}

void
LSMessage::SetHello ()
{
  if (m_messageType == 0)
    {
      m_messageType = HELLO;
    }
  else
    {
      NS_ASSERT (m_messageType == HELLO);
    }
  m_message.hello.msg = "hello";
}

LSMessage::Hello
LSMessage::GetHello ()
{
  return m_message.hello;
}

// HelloRSP

uint32_t
LSMessage::HelloRSP::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + msg.length();
  return size;
}

void
LSMessage::HelloRSP::Print (std::ostream &os) const
{
  os << "HelloRSP:: Message: " << msg << "\n";
}

void
LSMessage::HelloRSP::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (msg.length ());
  start.Write ((uint8_t *) (const_cast<char*> (msg.c_str())), msg.length());
}

uint32_t
LSMessage::HelloRSP::Deserialize (Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  msg = std::string (str, length);
  return HelloRSP::GetSerializedSize ();
}
void
LSMessage::SetHelloRsp()
{
  if (m_messageType == 0)
    {
      m_messageType = HELLO_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == HELLO_RSP);
    }
  m_message.helloRsp.msg = "helloRsp";
}

LSMessage::HelloRSP
LSMessage::GetHelloRsp ()
{
  return m_message.helloRsp;
}

//
//
//
//LS Update
uint32_t
LSMessage::LSUpdate::GetSerializedSize (void) const
{
  uint32_t size;
  size = 3*sizeof(uint32_t);
  return size;
}

void
LSMessage::LSUpdate::Print (std::ostream &os) const
{
  os << "LSUpdate:: Edge: " << node1 << " to "<<node2<< "\n";
}

void
LSMessage::LSUpdate::Serialize (Buffer::Iterator &start) const
{
  start.WriteU32(node1);
  start.WriteU32(node2);
  start.WriteU32(seq);
}

uint32_t
LSMessage::LSUpdate::Deserialize (Buffer::Iterator &start)
{
  node1 = start.ReadU32();
  node2 = start.ReadU32();
  seq = start.ReadU32();
  return LSUpdate::GetSerializedSize ();
}
void
LSMessage::SetLSUpdateRsp (uint32_t node1, uint32_t node2, uint32_t seq)
{
  m_message.lsUpdate.node1 = node1;
  m_message.lsUpdate.node2 = node2;
  m_message.lsUpdate.seq = seq;
}

LSMessage::LSUpdate
LSMessage::GetLSUpdate ()
{
  return m_message.lsUpdate;
}
//
//

void
LSMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

LSMessage::MessageType
LSMessage::GetMessageType () const
{
  return m_messageType;
}

void
LSMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t
LSMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
LSMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t
LSMessage::GetTTL (void) const
{
  return m_ttl;
}

void
LSMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
LSMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}

