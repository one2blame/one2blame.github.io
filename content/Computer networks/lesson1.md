---
title: OSI model
tags:
  - osi
  - model
  - layered
  - architecture
  - spanning
  - tree
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson
1:

- What are advantages and disadvantages of a layered architecture?

  - Layered architectures provide the following advantages:

    - Scalability
    - Modularity
    - Flexibility

  - Layered architectures provide the following disadvantages:
    - Some layers' functionality depends on the information from other layers,
      violating the goals of separation.
    - One layer may duplicate lower layer functionalities. For example, error
      recovery occurring in multiple layers.
    - Additional overhead is incurred by the abstraction necessary between
      layers.

- What are the differences and similarities of the OSI model and five-layered
  Internet model?

  - The **OSI model** and the **Five-layered Internet model** contain the
    following similarities: _ Physical Layer _ Data Link Layer _ Network Layer _
    Transport Layer

  - The OSI model and the Five-layered Internet model are different in that the
    Five-layered Internet model condenses the **Application Layer**,
    **Presentation Layer**, and the **Session Layer** into the **Application
    Layer**.

- What are sockets?

  - The interface between the application layer and the transport layer.

- Describe each layer of the OSI model

  - **Application Layer**

    - Includes multiple protocols:
      - HTTP
      - SMTP
      - FTP
      - DNS
    - This layer offers multiple services depending upon the applications'
      implementations. Each major application is tied to a protocol. At this
      layer, packets of information are referred to as messages.

  - **Presentation Layer**

    - Plays the intermediate role of formatting the information that it receives
      from the layer below and delivers it to the Application layer.

  - **Session Layer**

    - Layer responsible for managing different transport streams that belong to
      session between end-user applications.

  - **Transport Layer**

    - Responsible for end-to-end communication between end-point hosts. This
      layer implements two transport protocols, **TCP** and **UDP**.
    - Packets of information at this layer are referred to as segments.

  - **Network Layer**

    - Responsible for moving datagrams from one Internet host to another. This
      layer implements the **IP** protocol, defining the structure of datagrams,
      how datagram information is processed, and routing protocols used to
      determine routes between hosts.
    - Packets of information at this layer are referred to as datagrams.

  - **Data Link Layer**

    - This layer is responsible for moving frames from one node to the next,
      after receiving the Network Layer's datagram. This layer offers services
      across the link between two nodes (e.g. reliable delivery). _ Example
      protocols implemented at this layer are: _ Ethernet _ Point to Point
      Protocol (PPP) _ IEEE 802.11
    - Packets of information at this layer are referred to as frames.

  - **Physical Layer**
    - This layer facilitates the interaction with the actual hardware and is
      responsible for transferring bits of a frame between two nodes connected
      through a physical link.
    - Main protocols include:
      - Twisted-pair copper wire
      - Coaxial
      - Single-mode fiber optics

- What is encapsulation, and how is it used in a layered model?

  - **Encapsulation**

    - At each layer the message is a combination of two parts:
      - The payload which is the message from the layer above
      - The new appended header information

  - **De-encapsulation**
    - At the receiving end, the process is reversed, with headers being stripped
      off at each layer.

- What is the end-to-end (e2e) principle?

  - The e2e principle suggests that specific application-level functions usually
    cannot, and preferably should not be built into the lower levels of the
    system at the core of the network.

- What are the examples of a violation of e2e principle?

  - Violations of the e2e principle typically refer to scenarios where it is not
    possible to implement a functionality entirely at the end hosts, such as NAT
    and firewalls.

- What is the EvoArch model?

  - A research model that can help to study layered architectures and their
    evolution in a quantitative manner. Through this model researchers were able
    to explain how the hierarchical structure of the layer architecture
    eventually lead to the hourglass shape.

- Explain a round in the EvoArch model

  - Introduce new nodes and place them randomly at layers
  - Examine all layers from top to bottom and perform:
    - Connect new nodes at each layer by choosing substrates (lower layer node)
      based on the generality probabilities of the layer below and choosing
      products (higher layer) based on the generality probability of the current
      layer
    - Update the value of each node at this layer
    - Examine all nodes in order of decreasing value in the layer and remove
      nodes that should die
  - Stop when we reach a given number of nodes

- What are the ramifications of the hourglass shape of the internet?

  - Many technologies that were not originally designed for the internet have
    been modified so that they have versions that can communicate over the
    internet (such as Radio over IP).
  - It has been a difficult and slow process to transition to IPv6, despite the
    shortage of public IPv4 addresses.

- Repeaters, hubs, bridges, routers operate on which layers?

  - **Repeaters** and **hubs** operate on Layer 1 (Physical layer).
  - **Bridges** operate on Layer 2 (Data-link layer).
  - **Routers** operate on Layer 3 (Network layer)

- What is a bridge, and how does it “learn”?

  - A device with multiple inputs/outputs that transfers frames from an input to
    one or multiple outputs. It learns from each frame it receives by populating
    a forwarding table so that it forwards frames on specific ports instead of
    broadcasting everywhere.

- What is a distributed algorithm?

  - Direct nodes send information to one another, and then they resend their
    results back after performing their own calculations, so the calculations
    are not happening in a centralized manner.

- Explain the Spanning Tree Algorithm

  - Runs in rounds. Each node first thinks it is the root. Each node sends a
    configuration message with the sending node’s ID, root as perceived by this
    node, and number of hops from this node to its root. When a node receives a
    message, it updates its root if it finds a lower ID root, better path to the
    root, or equal path to the root if the sender of the message has a lower ID.

- What is the purpose of the Spanning Tree Algorithm?

  - Prevent forwarding loops by excluding links that lead to loops (i.e. helps
    to prevent broadcast storms).
