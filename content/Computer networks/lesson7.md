---
title: Lesson 7
tags:
  - software
  - define
  - network
  - sdn
  - qos
  - cs6250
---

The following are questions and answers from the Exam 2 Study Guide for Lesson 7:

- What spurred the development of Software Defined Networking (SDN)?

  - SDN arose as part of the process to make computer networks more programmable . Due to a
    diversity of equipment and the requirement to handle different proprietary technologies from
    different vendors for different network devices, SDN works to redesign networks to make them
    more manageable.

- What are the three phases in the history of SDN?

  1. Active networks
  2. Control and data plane separation
  3. OpenFlow API and network operating systems

- Summarize each phase in the history of SDN.

  1. Packaging of code in network packets to create flows / QoS for different packet types. Most of
     this occurred at the edge of the network. Code was executed inside of Virtual Machines.
     Backbone network managers were not comfortable with arbitrary code execution by any developer
     on network nodes.

  2. Packet forwarding was implemented directly in the hardware. This era tailored to administrators
     being able to control / manage routing decisions. Emphasized programmability in the control
     domain rather than the data domain.

  3. The vision of fully programmable networks for research is realized, and then actually used by
     businesses / ISPs. Abstracted away the specifics of vendor software / proprietary products and
     allowed the entire network to be treated as one programmable entity. Lead to the rise of
     network operating systems and distributed state management.

- What is the function of the control and data planes?

  - The control plane contains the logic that implements the forwarding behavior of routers such as
    routing protocols and network middlebox configurations.
  - The data plane performs the actual forwarding as dictated by the control plane.

- Why separate the control from the data plane?

  - Independent evolution and development - prior to their separation, any changes to the control
    plane had to be met with upgrades to the hardware.
  - Control from high-level software programs - software computes the forwarding tables in SDN,
    allowing us to use high-order or more abstract programming languages to implement routing
    algorithms. This also makes debugging and checking the behavior of the network easier.

- Why did the SDN lead to opportunities in various areas such as data centers, routing, enterprise
  networks, and research network?

  1. Data centers - SDN assists in the management of large data centers with thousands of servers
     and VMs.
  2. Routing - SDN has the capability to make routing decisions using multiple criteria, and can
     easily update a router's state for the implementation of BGP policies. This provides mre
     control over path selection.
  3. Enterprise networks - SDN improves security applications for enterprise networks. An example
     being dropping attack traffic at strategic locations within the network to mitigate the effects
     of a DDoS attack.
  4. Research networks - SDN enables research networks to coexist with production networks (they so
     easy to create and tear down).

- What is the relationship between forwarding and routing?

  - In forwarding, the router inspects the packet coming in from a port, consults the routing table,
    and sends the packet to the output port dictated by the forwarding table. Forwarding is a
    function of the data plane.
  - In routing, routers use routing algorithms to generate the forwarding table, implementing
    policies and using these algorithms to determine the best path for traffic. Routing is a
    function of the control plane.

- What is the difference between a traditional and SDN approach in terms of coupling of control and
  data plane?

  - In the traditional approach, the control and data planes are closely coupled. The router runs
    routing algorithms and generates the forwarding table . In the SDN approach, the remote
    controller computers and distributes forwarding tables. The controller is physically separated
    from the router.

- What are the main components of SDN network and their responsibilities?

  - SND-controlled network elements - infrastructure layer, responsible for forwarding traffic using
    rules computed by the SDN control plane.
  - SDN controller - logically centralized entity that behaves as an interface between the network
    elements and the network-control applications.
  - Network-control applications - programs that manage the underlying network by collecting
    information about the network elements with the help of the SDN controller.

- What are the four defining features in an SDN architecture?

  - Flow-base forwarding - rules for packets can be computed based on any number of header field
    values in various layers (transport, network, link).
  - Separation of data and control planes
  - Network control functions - controller maintains up-to-date network state information and
    provides it to the network-control applications. This enables network-control applications to
    monitor and control network devices.
  - Programmable network - enables the implementation of sophisticated routing applications to
    include network management, traffic engineering, security, automation, analytics, etc.

- What are the three layers of SDN controller?

  - Communication layer - comms between the controller and the network elements
  - Network-wide state-management layer - stores information about the network state
  - Interface to the network-control application layer - communication between controller and
    network-control applications
