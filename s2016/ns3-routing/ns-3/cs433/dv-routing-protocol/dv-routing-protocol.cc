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


#include "ns3/dv-routing-protocol.h"
#include "ns3/socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-route.h"
#include "ns3/uinteger.h"
#include "ns3/test-result.h"
#include <sys/time.h>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DVRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (DVRoutingProtocol);

#define MAX_DISTANCE 16;
#define min(a, b) (((a) < (b)) ? (a) : (b))

static const uint32_t INTERFACE_ANY = 0xffffffff;

TypeId
DVRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVRoutingProtocol")
  .SetParent<CommRoutingProtocol> ()
  .AddConstructor<DVRoutingProtocol> ()
  .AddAttribute ("DVPort",
                 "Listening port for DV packets",
                 UintegerValue (6000),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_dvPort),
                 MakeUintegerChecker<uint16_t> ())
  .AddAttribute ("PingTimeout",
                 "Timeout value for PING_REQ in milliseconds",
                 TimeValue (MilliSeconds (2000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_pingTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("MaxTTL",
                 "Maximum TTL value for DV packets",
                 UintegerValue (16),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_maxTTL),
                 MakeUintegerChecker<uint8_t> ())
  .AddAttribute ("HelloTimeout",
                 "Timeout value for HELLO in milliseconds",
                 TimeValue(MilliSeconds (20000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_helloTimeout), MakeTimeChecker ())
  ;
  return tid;
}

DVRoutingProtocol::DVRoutingProtocol ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentSequenceNumber = random.GetInteger ();
  // Setup static routing 
  m_staticRouting = Create<Ipv4StaticRouting> ();
}

DVRoutingProtocol::~DVRoutingProtocol ()
{
}

void 
DVRoutingProtocol::DoDispose ()
{
  // Close sockets
  for (std::map< Ptr<Socket>, Ipv4InterfaceAddress >::iterator iter = m_socketAddresses.begin ();
       iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  
  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel ();
  m_sayHelloTimer.Cancel();
 
  m_pingTracker.clear ();
  m_helloTracker.clear();

  CommRoutingProtocol::DoDispose ();
}

void
DVRoutingProtocol::SetMainInterface (uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress (mainInterface, 0).GetLocal ();
}

void
DVRoutingProtocol::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
DVRoutingProtocol::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
DVRoutingProtocol::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    { 
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

uint32_t
DVRoutingProtocol::ReverseLookupInt (Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find (ipAddress);
  if (iter != m_addressNodeMap.end ())
    {
      uint32_t nodeNumber = iter->second;
      return nodeNumber;
    }
  return 0;
}

std::string
DVRoutingProtocol::ReverseLookup (Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find (ipAddress);
  if (iter != m_addressNodeMap.end ())
    { 
      std::ostringstream sin;
      uint32_t nodeNumber = iter->second;
      sin << nodeNumber;    
      return sin.str();
    }
  return "Unknown";
}

void
DVRoutingProtocol::DoStart ()
{
  // Create sockets
  for (uint32_t i = 0 ; i < m_ipv4->GetNInterfaces () ; i++)
    {
      Ipv4Address ipAddress = m_ipv4->GetAddress (i, 0).GetLocal ();
      if (ipAddress == Ipv4Address::GetLoopback ())
        continue;
      // Create socket on this interface
      Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
          UdpSocketFactory::GetTypeId ());
      socket->SetAllowBroadcast (true);
      InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), m_dvPort);
      socket->SetRecvCallback (MakeCallback (&DVRoutingProtocol::RecvDVMessage, this));
      if (socket->Bind (inetAddr))
        {
          NS_FATAL_ERROR ("DVRoutingProtocol::DoStart::Failed to bind socket!");
        }
      Ptr<NetDevice> netDevice = m_ipv4->GetNetDevice (i);
      socket->BindToNetDevice (netDevice);
      m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);
    }
  m_helloTracker.reserve(10);

  // Initialize our distance vector with distances to all nodes set to maximum distance
  std::map<uint32_t, Ipv4Address>::iterator it;
  for (it = m_nodeAddressMap.begin(); it != m_nodeAddressMap.end(); ++it) {
    routing_table[it->first] = ReverseLookupInt(m_mainAddress);

    dv[it->first] = MAX_DISTANCE;
    if (IsOwnAddress(ResolveNodeIpAddress(it->first))) {
      dv[it->first] = 0;
    }

    m_neighbors[it->first] = MAX_DISTANCE;
  }

  // Configure timers
  m_auditPingsTimer.SetFunction (&DVRoutingProtocol::AuditPings, this);
  m_sayHelloTimer.SetFunction(&DVRoutingProtocol::SayHelloToNeighbors, this);

  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  m_sayHelloTimer.Schedule(m_helloTimeout);
}

Ptr<Ipv4Route>
DVRoutingProtocol::RouteOutput (Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput (packet, header, outInterface, sockerr);
  if (ipv4Route)
    {
      DEBUG_LOG ("Found route to: " << ipv4Route->GetDestination () << " via next-hop: " << ipv4Route->GetGateway () << " with source: " << ipv4Route->GetSource () << " and output device " << ipv4Route->GetOutputDevice());
    }
  else
    {
      DEBUG_LOG ("No Route to destination: " << header.GetDestination ());
    }
  return ipv4Route;
}

bool 
DVRoutingProtocol::RouteInput  (Ptr<const Packet> packet, 
  const Ipv4Header &header, Ptr<const NetDevice> inputDev,                            
  UnicastForwardCallback ucb, MulticastForwardCallback mcb,             
  LocalDeliverCallback lcb, ErrorCallback ecb)
{
  Ipv4Address destinationAddress = header.GetDestination ();
  Ipv4Address sourceAddress = header.GetSource ();

  // Drop if packet was originated by this node
  if (IsOwnAddress (sourceAddress) == true)
    {
      return true;
    }

  // Check for local delivery
  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice (inputDev);
  if (m_ipv4->IsDestinationAddress (destinationAddress, interfaceNum))
    {
      if (!lcb.IsNull ())
        {
          lcb (packet, header, interfaceNum);
          return true;
        }
      else
        {
          return false;
        }
    }

  // Check static routing table
  if (m_staticRouting->RouteInput (packet, header, inputDev, ucb, mcb, lcb, ecb))
    {
      return true;
    }
  DEBUG_LOG ("Cannot forward packet. No Route to destination: " << header.GetDestination ());
  return false;
}

void
DVRoutingProtocol::BroadcastPacket (Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_dvPort));
    }
}

void
DVRoutingProtocol::SendPacket (Ptr<Packet> packet, Ipv4Address dest)
{
  m_socketAddresses.begin()->first->SendTo (packet, 0, InetSocketAddress (dest, m_dvPort));
}

void
DVRoutingProtocol::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params..."); 
          return;
        }
      iterator++;
      std::istringstream sin (*iterator);
      uint32_t nodeNumber;
      sin >> nodeNumber;
      iterator++;
      std::string pingMessage = *iterator;
      Ipv4Address destAddress = ResolveNodeIpAddress (nodeNumber);
      if (destAddress != Ipv4Address::GetAny ())
        {
          uint32_t sequenceNumber = GetNextSequenceNumber ();
          TRAFFIC_LOG ("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " SequenceNumber: " << sequenceNumber);
          Ptr<PingRequest> pingRequest = Create<PingRequest> (sequenceNumber, Simulator::Now(), destAddress, pingMessage);
          // Add to ping-tracker
          m_pingTracker.insert (std::make_pair (sequenceNumber, pingRequest));
          Ptr<Packet> packet = Create<Packet> ();
          DVMessage dvMessage = DVMessage (DVMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
          dvMessage.SetPingReq (destAddress, ResolveNodeIpAddress(routing_table[ReverseLookupInt(destAddress)]), pingMessage);
          packet->AddHeader (dvMessage);

          PRINT_LOG("\nNode " << LocalNode() << ": sending PING_REQ to node " << nodeNumber << ". Message: " << pingMessage);

          // Send packet along to the next hop
          BroadcastPacket(packet);
        }
    }
  else if (command == "DUMP")
    {
      if (tokens.size() < 2)
        {
          ERROR_LOG ("Insufficient Parameters!");
          return;
        }
      iterator++;
      std::string table = *iterator;
      if (table == "ROUTES" || table == "ROUTING")
        {
          DumpRoutingTable ();
        }
      else if (table == "NEIGHBORS" || table == "NEIGHBOURS")
        {
          DumpNeighbors ();
        }
      else if (table == "DV")
        {
          DumpDV ();
        }
    }
}

void
DVRoutingProtocol::DumpDV()
{
  STATUS_LOG (std::endl << "**************** DV DUMP ********************" << std::endl
              << "Node\tDistance to node");

  std::map<uint32_t, uint32_t>::iterator it;
  for (it = dv.begin(); it != dv.end(); ++it) {
    PRINT_LOG ("" << it->first << "\t" << it->second);
  }
}

void
DVRoutingProtocol::DumpNeighbors ()
{
  STATUS_LOG (std::endl << "**************** Neighbor List ********************" << std::endl
              << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");

  std::map<uint32_t, uint32_t>::iterator it;
  for (it = m_neighbors.begin(); it != m_neighbors.end(); ++it) 
  {
    if (it->second == 1) {
      uint32_t node = it->first;
      PRINT_LOG(""<<node<<"\t\t\t"<<ResolveNodeIpAddress(node)<<"\t\t"<<m_socketAddresses.begin()->second.GetLocal());
      checkNeighborTableEntry(node, ResolveNodeIpAddress(node), m_socketAddresses.begin()->second.GetLocal());
    }
  }

  /*NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
  // checkNeighborTableEntry();
}

void
DVRoutingProtocol::DumpRoutingTable ()
{
  STATUS_LOG (std::endl << "**************** Route Table ********************" << std::endl
              << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");

  std::map<uint32_t, uint32_t>::iterator it;
  for (it = routing_table.begin(); it != routing_table.end(); ++it) {
    uint32_t destNode = it->first;
    uint32_t nextHopNode = it->second;
    PRINT_LOG(""<<destNode<<"\t\t\t"<<ResolveNodeIpAddress(destNode)<<"\t\t"
            <<nextHopNode<<"\t\t\t"<<ResolveNodeIpAddress(nextHopNode)<<"\t\t"
            <<m_socketAddresses.begin()->second.GetLocal()<<"\t\t"<<dv[destNode]);
    checkRouteTableEntry(destNode, ResolveNodeIpAddress(destNode), nextHopNode, ResolveNodeIpAddress(nextHopNode),
                         m_socketAddresses.begin()->second.GetLocal(), dv[destNode]);
  }

  /*NOTE: For purpose of autograding, you should invoke the following function for each
  routing table entry. The output format is indicated by parameter name and type.
  */
  //checkRouteTableEntry();
}

void
DVRoutingProtocol::RecvDVMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  DVMessage dvMessage;
  packet->RemoveHeader (dvMessage);

  switch (dvMessage.GetMessageType ())
    {
      case DVMessage::PING_REQ:
        ProcessPingReq (dvMessage);
        break;
      case DVMessage::PING_RSP:
        ProcessPingRsp (dvMessage);
        break;
      case DVMessage::HELLO:
        ProcessHello(dvMessage, sourceAddress);
        break;
      case DVMessage::HELLO_RSP:
        ProcessHelloRsp(ReverseLookupInt(dvMessage.GetOriginatorAddress ()));
        break;
      case DVMessage::DISTANCE_VECTOR_ADVERTISEMENT:
        ProcessDV(dvMessage, ReverseLookupInt(dvMessage.GetOriginatorAddress()));
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
DVRoutingProtocol::ProcessPingReq (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingReq().destinationAddress)) {
      std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());

      PRINT_LOG("Node " << LocalNode() << ": received PING_REQ from node " << fromNode << ". Message: " << dvMessage.GetPingReq().pingMessage << "... Sending response");

      TRAFFIC_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << dvMessage.GetPingReq().pingMessage);
      // Send Ping Response
      DVMessage dvResp = DVMessage (DVMessage::PING_RSP, dvMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
      dvResp.SetPingRsp (dvMessage.GetOriginatorAddress(), ResolveNodeIpAddress(routing_table[ReverseLookupInt(dvMessage.GetOriginatorAddress())]), dvMessage.GetPingReq().pingMessage);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (dvResp);

      BroadcastPacket(packet);
    }
  else if (IsOwnAddress(dvMessage.GetPingReq().nextHop)) {
      PRINT_LOG("Node " << LocalNode() << ": forwarding PING_REQ to node " << routing_table[ReverseLookupInt(dvMessage.GetPingReq().destinationAddress)]);

      Ptr<Packet> packet = Create<Packet> ();
      dvMessage.SetPingReqNextHop(ResolveNodeIpAddress(routing_table[ReverseLookupInt(dvMessage.GetPingReq().destinationAddress)]));
      packet->AddHeader (dvMessage);
      BroadcastPacket(packet);
  }
}

void
DVRoutingProtocol::ProcessPingRsp (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingRsp().destinationAddress)) {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
    iter = m_pingTracker.find (dvMessage.GetSequenceNumber ());
    if (iter != m_pingTracker.end ())
      {
        std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());

        PRINT_LOG("Node " << LocalNode() << ": received PING_RSP from node " << fromNode << ". Message: " << dvMessage.GetPingRsp().pingMessage);

        TRAFFIC_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << dvMessage.GetPingRsp().pingMessage);
        m_pingTracker.erase (iter);
      }
    else
      {
        DEBUG_LOG ("Received invalid PING_RSP!");
      }
  }
  else if (IsOwnAddress(dvMessage.GetPingRsp().nextHop)) {
    PRINT_LOG("Node " << LocalNode() << ": forwarding PING_RSP to node " << routing_table[ReverseLookupInt(dvMessage.GetPingReq().destinationAddress)]);

    Ptr<Packet> packet = Create<Packet> ();
    dvMessage.SetPingRspNextHop(ResolveNodeIpAddress(routing_table[ReverseLookupInt(dvMessage.GetPingReq().destinationAddress)]));
    packet->AddHeader (dvMessage);
    BroadcastPacket(packet);
  }
}

void
DVRoutingProtocol::ProcessHello (DVMessage dvMessage, Ipv4Address sourceAddress)
{
  // add hello to neighbors table
  if (m_neighbors[ReverseLookupInt(sourceAddress)] != 1) {
    m_neighbors[ReverseLookupInt(sourceAddress)] = 1;
    UpdateDV();
  }

  DVMessage dvResp = DVMessage (DVMessage::HELLO_RSP, dvMessage.GetSequenceNumber(), 1, m_mainAddress);
  dvResp.SetHelloRsp();
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (dvResp);
  SendPacket(packet, sourceAddress);
}

void
DVRoutingProtocol::ProcessHelloRsp (uint32_t node)
{
  if (m_neighbors[node] != 1) {
    m_neighbors[node] = 1;
    UpdateDV();
  }
  std::vector<uint32_t>::iterator it;
  if ((it = std::find(m_helloTracker.begin(), m_helloTracker.end(), node)) != m_helloTracker.end()) {
    m_helloTracker.erase(it);
  }
}

void
DVRoutingProtocol::SayHelloToNeighbors() {
  // any neighbors that haven't responded since last hello are assumed to be down;
  // update costs & DV accordingly
  for(int i=0; i<m_helloTracker.size(); i++){
    m_neighbors[m_helloTracker[i]] = MAX_DISTANCE;
  }
  if (m_helloTracker.size() != 0) {
    UpdateDV();
  }
  m_helloTracker.clear();

  std::map<uint32_t, uint32_t>::iterator it;
  for(it = m_neighbors.begin(); it != m_neighbors.end(); ++it)
  {
    // if cost of node is 1, then it is a live neighbor so we add it to hello_tracker
    if (it->second == 1) {
      m_helloTracker.push_back(it->first);
    }
  }

  Ptr<Packet> packet = Create<Packet> ();
  DVMessage dvMessage = DVMessage (DVMessage::HELLO, 0, 1, m_mainAddress);
  packet->AddHeader (dvMessage);
  BroadcastPacket (packet);

  m_sayHelloTimer.Schedule(m_helloTimeout);
}

void
DVRoutingProtocol::SendDVToNeighbors() {
  DVMessage dvAdvert = DVMessage(DVMessage::DISTANCE_VECTOR_ADVERTISEMENT, GetNextSequenceNumber(), 1, m_mainAddress);
  dvAdvert.SetDVA(dv);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader(dvAdvert);
  BroadcastPacket(packet);
}

void
DVRoutingProtocol::ProcessDV(DVMessage dvMessage, uint32_t node) {
  // delete this neighbor's old dv
  std::vector< std::pair<uint32_t, std::map<uint32_t, uint32_t> > >::iterator it;
  for (it = neighbor_dvs.begin(); it != neighbor_dvs.end(); ++it) {
    if (it->first == node) {
      neighbor_dvs.erase(it);
      break;
    }
  }

  // add the neighbors new dv back into our vector
  neighbor_dvs.push_back(std::make_pair(node, dvMessage.GetDVA().dv));

  UpdateDV();
}


void DVRoutingProtocol::UpdateDV() {
  bool dv_changed = false;

  // for each node in the network
  std::map<uint32_t, uint32_t>::iterator it;
  for (it = dv.begin(); it != dv.end(); ++it) {
    uint32_t node = it->first;
    uint32_t old_distance = dv[node];
    uint32_t min_distance = MAX_DISTANCE;

    uint32_t next_hop;

    // if node is a neighbor, set distance appropriately
    if (m_neighbors[node] == 1) {
      next_hop = node;
      min_distance = 1;
    }
    else if (IsOwnAddress(ResolveNodeIpAddress(node))){
      next_hop = node;
      min_distance = 0;
    }
    else {
      // default to next hop as own address (i.e. node is unreachable)
      next_hop = ReverseLookupInt(m_mainAddress);

      // find min neighbor cost + distance over all neighbors
      std::vector<std::pair<uint32_t, std::map<uint32_t, uint32_t> > >::iterator i;
      for (i = neighbor_dvs.begin(); i != neighbor_dvs.end(); ++i) {
        uint32_t neighbor = i->first;
        std::map<uint32_t, uint32_t> neighbor_dv = i->second;

        if (min_distance > min(m_neighbors[neighbor] + neighbor_dv[node], min_distance)) {
          // TODO remember the neighbor which corresponds to this condition & set it to be next hop in routing table
          // for route to this node
          min_distance = min(m_neighbors[neighbor] + neighbor_dv[node], min_distance);
          next_hop = neighbor;
        }
      }
    }

    dv[node] = min_distance;

    if (min_distance != old_distance) {
      m_staticRouting->AddHostRouteTo(ResolveNodeIpAddress(node), ResolveNodeIpAddress(next_hop), 1);
      routing_table[node] = next_hop;
      dv_changed = true;
    }
  }

  if (dv_changed) {
    // broadcast updated DV to neighbors
    SendDVToNeighbors();
  }
}

bool
DVRoutingProtocol::IsOwnAddress (Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4InterfaceAddress interfaceAddr = i->second;
      if (originatorAddress == interfaceAddr.GetLocal ())
        {
          return true;
        }
    }
  return false;

}

void
DVRoutingProtocol::AuditPings ()
{
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  for (iter = m_pingTracker.begin () ; iter != m_pingTracker.end();)
    {
      Ptr<PingRequest> pingRequest = iter->second;
      if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
        {
          DEBUG_LOG ("Ping expired. Message: " << pingRequest->GetPingMessage () << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds () << " CurrentTime: " << Simulator::Now().GetMilliSeconds ());
          // Remove stale entries
          m_pingTracker.erase (iter++);
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

uint32_t
DVRoutingProtocol::GetNextSequenceNumber ()
{
  return m_currentSequenceNumber++;
}

void 
DVRoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp (i);
}
void 
DVRoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown (i);
}
void 
DVRoutingProtocol::NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress (interface, address);
}
void 
DVRoutingProtocol::NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress (interface, address);
}

void
DVRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4 (m_ipv4);
}
