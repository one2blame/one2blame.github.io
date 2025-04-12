---
title: Routing
tags:
  - cidr
  - routing
  - control
  - plane
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson 5:

- What are the basic components of a router?

  - Input/output ports, switching fabric, and the routing processor

- Explain the forwarding (or switching) function of a router

  - The router’s action of transferring a packet from an input link interface to the appropriate
    output link interface. Forwarding takes place at very short timescales (typically a few
    nanoseconds), and is typically implemented in hardware.

- The switching fabric moves the packets from input to output ports. What are the functionalities
  performed by the input and output ports?

  - Inside the forwarding data plane (hardware) we have three main components:
    - **Input ports** - first they physically terminate the incoming links to the router, then they
      decapsulate packets, and finally (most importantly) they perform the lookup function by
      consulting the forwarding table to forward the packet to the appropriate output port through
      the switching fabric
    - **Switching fabric** - moves packets from input to output ports
    - **Output ports** - receive and queue packets from the switching fabric and send them over to
      the outgoing link

- What is the purpose of the router’s control plane?

  - Inside the control plane (software), we have the routing processor which implements the routing
    protocols, maintains the routing tables, and computes the forwarding tables.

- What tasks occur in a router?

  - **Lookup** - router looks at destination IP and consults forwarding table (FIB) to determine
    output link using longest prefix matching algorithms
  - **Switching** - aka forwarding this is the most important task of a router where the router
    transfers the packet from the input link to the output link.
  - **Queuing** - after the packet has been switched to a specific output port, it needs to be
    queued if the link is congested
  - **Header validation and checksum** - router checks the packet’s version number, decreases
    time-to-live field, and recalculates the header checksum
  - **Route processing** - routing processor uses routing protocols (such as OSPF/RIP) to build the
    forwarding tables
  - **Protocol processing** - routers need to use some protocols to implement their functions
    including SNMP, TCP and UDP, and ICMP

- List and briefly describe each type of switching. Which, if any, can send multiple packets across
  the fabric in parallel?

  1. **Via memory** - routing processor controls this method which involves the packet being copied
     to the processor’s memory, consulting the forwarding table, and copied the packet to the
     output’s port buffer. One packet at a time.
  2. **Via bus** - no routing processor involved - the input port puts an internal header which
     designates the output port and sends the packet to the shared bus. All output ports receive the
     packet but only the designated one keeps it. One packet at a time.
  3. **Via interconnection network** - crossbar switch used so that multiple packets can be carried
     at the same time as long as they are using different input and output ports.

- What are two fundamental problems involving routers, and what causes these problems?

  1. **Bandwidth and Internet population scaling** - caused by the increasing number of devices that
     connect to the Internet, heavier traffic from new apps, new technologies such as optical links
     that can handle higher volumes of traffic.
  2. **Services at high speeds** - new apps may require new services such as protection against
     delays in presence of congestion and protection during attacks/failures. Offering these
     services at very high speeds is a challenge for routers.

- What are the bottlenecks that routers face, and why do they occur?

  - Many bottlenecks including exact lookups, prefix lookups, packet classification, switching
    limitations, and security. Most are caused by scaling issues - the need for high speed and
    service guarantees.

- What is CIDR, and why was it introduced?

  - **Classless Internet Domain Routing** - introduced to help with scaling as we ran out of IP
    addresses so it allows IP addresses of arbitrary-length prefixes. This helped decrease router
    table size but introduced the longest-matching-prefix lookup problem.

- Name 4 takeaway observations around network traffic characteristics. Explain their consequences

  1. There are a large number of concurrent flows of short duration - therefore a caching solution
     would not work efficiently.
  2. Lookup speed is very important, a large part of the computational cost for lookup is in
     accessing memory.
  3. An unstable/inefficient routing protocol can lead to time increases
  4. Memory usage trade-off - either use fast, expensive memory (cache in software/SRAM) or cheaper
     but slower memory (DRAM)

- Why do we need multibit tries?

  - **Unibit tries** require too many memory accesses while **multibit tries** solve this by using a
    stride. A stride is the number of bits that we check at each step.

- What is prefix expansion, and why is it needed?

  - Expanding a given prefix to more prefixes so that we don’t miss out on any prefixes. Gives more
    speed with a cost of increased database size.

- What are the benefits of variable-stride versus fixed-stride multibit tries?

  - More optimized - takes up less space in prefix database, less memory access, more flexible.
