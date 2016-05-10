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

#include "ns3/dv-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DVMessage");
NS_OBJECT_ENSURE_REGISTERED (DVMessage);

DVMessage::DVMessage ()
{
}

DVMessage::~DVMessage ()
{
}

DVMessage::DVMessage (DVMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId 
DVMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVMessage")
    .SetParent<Header> ()
    .AddConstructor<DVMessage> ()
  ;
  return tid;
}

TypeId
DVMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
DVMessage::GetSerializedSize (void) const
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
      case DISTANCE_VECTOR_ADVERTISEMENT:
        size += m_message.dva.GetSerializedSize();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
DVMessage::Print (std::ostream &os) const
{
  os << "\n****DVMessage Dump****\n" ;
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
      case DISTANCE_VECTOR_ADVERTISEMENT:
        m_message.dva.Print (os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
DVMessage::Serialize (Buffer::Iterator start) const
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
      case DISTANCE_VECTOR_ADVERTISEMENT:
        m_message.dva.Serialize(i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
DVMessage::Deserialize (Buffer::Iterator start)
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
      case DISTANCE_VECTOR_ADVERTISEMENT:
        m_message.dva.Deserialize(i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
DVMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = (2 * IPV4_ADDRESS_SIZE) + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
DVMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteHtonU32(nextHop.Get());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  nextHop = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
DVMessage::SetPingReq (Ipv4Address destinationAddress, Ipv4Address nextHop, std::string pingMessage)
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
  m_message.pingReq.nextHop = nextHop;
  m_message.pingReq.pingMessage = pingMessage;
}

void DVMessage::SetPingReqNextHop(Ipv4Address nextHop) {
  m_message.pingReq.nextHop = nextHop;
}

DVMessage::PingReq
DVMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
DVMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = (2 * IPV4_ADDRESS_SIZE) + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
DVMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteHtonU32(nextHop.Get());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  nextHop = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
DVMessage::SetPingRsp (Ipv4Address destinationAddress, Ipv4Address nextHop, std::string pingMessage)
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
  m_message.pingRsp.nextHop = nextHop;
  m_message.pingRsp.pingMessage = pingMessage;
}

void DVMessage::SetPingRspNextHop(Ipv4Address nextHop) {
  m_message.pingRsp.nextHop = nextHop;
}

DVMessage::PingRsp
DVMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


// Hello

uint32_t 
DVMessage::Hello::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + msg.length();
  return size;
}

void
DVMessage::Hello::Print (std::ostream &os) const
{
  os << "Hello:: Message: " << msg << "\n";
}

void
DVMessage::Hello::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (msg.length ());
  start.Write ((uint8_t *) (const_cast<char*> (msg.c_str())), msg.length());
}

uint32_t
DVMessage::Hello::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  msg = std::string (str, length);
  return Hello::GetSerializedSize ();
}

void
DVMessage::SetHello ()
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

DVMessage::Hello
DVMessage::GetHello ()
{
  return m_message.hello;
}

// HelloRSP

uint32_t 
DVMessage::HelloRSP::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + msg.length();
  return size;
}

void
DVMessage::HelloRSP::Print (std::ostream &os) const
{
  os << "HelloRSP:: Message: " << msg << "\n";
}

void
DVMessage::HelloRSP::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (msg.length ());
  start.Write ((uint8_t *) (const_cast<char*> (msg.c_str())), msg.length());
}

uint32_t
DVMessage::HelloRSP::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  msg = std::string (str, length);
  return HelloRSP::GetSerializedSize ();
}
void
DVMessage::SetHelloRsp ()
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

DVMessage::HelloRSP
DVMessage::GetHelloRsp ()
{
  return m_message.helloRsp;
}

void DVMessage::DistanceVectorAdvertisement::Print (std::ostream &os) const {
  os << "DistanceVectorAdvertisement::dv = ...\n";
  for (std::map<uint32_t, uint32_t>::const_iterator it = dv.begin(); it != dv.end(); ++it) {
    os << "first (node): " << it->first << " and second (distance): " << it->second;
  }
}

uint32_t DVMessage::DistanceVectorAdvertisement::GetSerializedSize (void) const {
  return sizeof(uint16_t) + (dv.size() * (2 * sizeof(uint32_t)));
}

void DVMessage::DistanceVectorAdvertisement::Serialize (Buffer::Iterator &start) const {
  start.WriteU16(dv.size());
  for (std::map<uint32_t, uint32_t>::const_iterator it = dv.begin(); it != dv.end(); ++it) {
    start.WriteHtonU32(it->first);
    start.WriteHtonU32(it->second);
  }
}

uint32_t DVMessage::DistanceVectorAdvertisement::Deserialize (Buffer::Iterator &start) {
  uint16_t length = start.ReadU16 ();

  for (int i = 0; i < length; ++i) {
    uint32_t key = start.ReadNtohU32();
    uint32_t value = start.ReadNtohU32();
    dv[key] = value;
  }

  return DistanceVectorAdvertisement::GetSerializedSize();
}

DVMessage::DistanceVectorAdvertisement DVMessage::GetDVA() {
  return m_message.dva;
}

void DVMessage::SetDVA(std::map<uint32_t, uint32_t> local_dv) {
  if (m_messageType == 0)
    {
      m_messageType = DISTANCE_VECTOR_ADVERTISEMENT;
    }
  else
    {
      NS_ASSERT (m_messageType == DISTANCE_VECTOR_ADVERTISEMENT);
    }
  m_message.dva.dv = local_dv;
}

//
//
//

void
DVMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

DVMessage::MessageType
DVMessage::GetMessageType () const
{
  return m_messageType;
}

void
DVMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t 
DVMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
DVMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t 
DVMessage::GetTTL (void) const
{
  return m_ttl;
}

void
DVMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
DVMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}

