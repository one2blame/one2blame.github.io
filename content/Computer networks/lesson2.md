---
title: Transport layer
tags:
  - transport
  - layer
  - tcp
  - udp
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson
2:

- What does the Transport Layer provide?

  - The Transport Layer provides an end-to-end connection between two
    applications that are running on different hosts, regardless if the hosts
    are in the same network.

- What is a packet for the Transport Layer called?

  - Packets at the Transport Layer are called segments.

- What are the two main protocols within the Transport Layer?

  - The two main protocols within the Transport Layer are:
    - Transmission Control Protocol (TCP)
    - User Datagram Protocol (UDP)

- What is multiplexing, and why is it necessary?

  - The Transport Layer utilizes ports to implement **multiplexing**, allowing
    hosts to utilize the network for multiple applications. Multiplexing allows
    multiple streams of information to exist on the same network, and the
    division of the streams to different applications at the endpoint is
    achieved using ports.

- Describe the two types of multiplexing/demultiplexing

  - The two types of multiplexing / demultiplexing are **connectionless** and
    **connection-oriented**: _ **connectionless** multiplexing / demultiplexing
    uses UDP and only requires the destination IP address and destination port.
    _ **connection-oriented** multiplexing / demultiplexing uses TCP and
    requires the source IP address, source port, destination IP address and
    destination port.

- What are the differences between UDP and TCP?

  - TCP provides end-to-end communication and reliability.
  - UDP offers no congestion control or similar mechanisms and no connection
    management overhead. The Application Layer must implement these features, if
    necessary.

- When would an application layer protocol choose UDP over TCP?

  - UDP is useful for real-time applications that are sensitive to delays. The
    following are some applications / protocols that utilize UDP: _ Remote file
    servers _ Streaming multimedia _ Internet telephony / VOIP _ Network
    management _ Routing protocols (e.g. RIP) _ Name translation (i.e. DNS)

- Explain the TCP Three-way Handshake

  - The TCP three-way handshake is the TCP protocol's method of initiating a
    connection with a host. TCP segments contain flags that are used to send TCP
    specific messages related to the protocol. For the three-way handshake, the
    flags `SYN` and `ACK` are used. The host initiating the connection begins by
    sending the remote host a `SYN` TCP message. The remote host responds with a
    `SYN, ACK` TCP message. Finally, the initiating host responds with an `ACK`
    TCP message, establishing the session - from there the Application Layer
    takes over to utilize the session for TCP-centric applications.

  - The initial `SYN` TCP message and the `SYN, ACK` message from the server
    both contain a random sequence number. Each number will be incremented by
    `1` each time the two hosts communicate using TCP.

- Explain the TCP connection tear down

  - When the client is ready to close the connection, it sends a `FIN` TCP
    segment to the server. The server responds with an `ACK` TCP segment. When
    the server has completed its destruction of the TCP connection, it sends a
    `FIN` TCP segment to the client, and the client responds with `ACK`.

- What is Automatic Repeat Request or ARQ?

  - TCP segments contain a segment number, allowing both hosts to know which
    segments were sent or received. Using TCP, hosts can acknowledge that they
    receive specific segments, allowing sending hosts to know if the receiver
    received all of the segments or if the receiver missed specific segments. If
    a specific segment is not acknowledged by the receiver, the sender can
    assume the segment didn't reach the receiver - after a timeout it will
    resend the segment. This is **ARQ**.

- What is Stop and Wait ARQ?

  - This is what I described in the previous paragraph - sending and receiving
    with a timeout for acknowledged segments.

- What is Go-back-N?

  - A modification of **Stop and Wait ARQ** that is more performant.
    Essentially, the receiver only acknowledges the most recently received, in
    order segment. So if the sender sends 10 segments, and the receiver
    acknowledges segment 7, then the receiver knows that maybe 8, 9, or 10 were
    either received out of order or lost entirely. Thus, the sender will resend
    the entire window of 1-10 segments. The receiver will disregard 1-7 because
    it already has them, but will hopefully acknowledge segment 10, meaning it
    got the entire window of segments.

- What is selective ACKing?

  - This is another mutation of the above protocols, however, the receiver can
    now receive segments out of order. The sender can now know that some
    segments were dropped or corrupted on their trip to the receiver. Once the
    entire window is received by the receiver, it will place the segments back
    into the correct order and proceed to the Application Layer.

- What is fast retransmit?

  - This occurs when the receiver is encountering duplicate acknowledgements for
    segments that have already been acknowledged by the receiver. The sender
    will resend the segment experiencing duplicate acknowledgements.

- What is transmission control and why do we need to control it?

  - Transmission control is used to control how much data is sent over a link by
    applications in used by each host on the network. Transmission control
    implements fairness on the network and congestion control for Layer 3
    devices that provide connectivity.

- What is flow control and why do we need to control it?

  - Flow control controls the transmission rate to protect a receiving host's
    network buffer from overflowing with information. It's possible that a
    receiving host is involved with multiple processes and does not read data
    from its network buffer instantly. This could cause an accumulation of data
    that overflows its buffer.

- What is congestion control?

  - While Flow control is concerned about one specific host, Congestion Control
    is concerned with protecting the entire network from congestion. Given
    multiple devices using the same link, Congestion Control aims to avoid the
    link reaching max capacity, thus causing dropped packets and
    retransmissions.

- What are the goals of the congestion control?

  - The goals of congestion control are as follows:
    - Efficiency - high throughput and network utilization.
    - Fairness - every host should get a fair share of the network bandwidth.
    - Low delay
    - Fast convergence - network flow should be able to quickly converge to fair
      allocation.

- What is network-assisted congestion control?

  - Network-assisted congestion control involves Layer 3 devices providing
    feedback to hosts on the congestion of the network. This is usually
    implemented by sending diagnostic ICMP messages.

- What is end-to-end congestion control?

  - The network does not provide any feedback to hosts about the congestion of
    the network to end points. Hosts must infer network behavior and adapt their
    transmission rate.

- How does a host infer congestion?

  - Two methods, both implemented via TCP:
    - Round trip delay - time based inference of network congestion. Difficult
      to implement because round trip time varies wildly.
    - Packet loss - the TCP messages that have to be re-sent, the more we can
      infer that network congestion exists. This was the first method of network
      congestion implemented in TCP.

- How does a TCP sender limit the sending rate?

  - TCP uses a congestion window, similar to the receive window for flow control
    by receiving hosts. TCP probes and adapts the congestion window, increasing
    to try and achieve the highest through, and decreasing when enough segments
    are dropped.

- Explain Additive Increase/Multiplicative Decrease (AIMD) in the context of TCP

  - TCP uses addition to increase the number of packets sent in the congestion
    window when the network is not experiencing congestion. Once congestion is
    detected, the window is decreased by some multiplicative value, generating a
    sawtooth pattern of traffic over time.

- What is a slow start in TCP?

  - Instead of using addition to establish the initial size of the congestion
    window, TCP will exponentially increase the congestion window until
    congestion is experienced.

- Is TCP fair in the case two where connections have the same RTT? Explain

  - Yes as both will increase and decrease window sizes as needed to balance.

- Is TCP fair in the case where two connections have different RTTs? Explain

  - No, a shorter RTT would increase the window faster.

- Explain how TCP CUBIC works

  - TCP CUBIC uses a cubic function for the calculation of its congestion
    window. When TCP CUBIC detects congestions, it exercises a multiplicative
    decrease on its congestion window. Afterwards, it greatly increases its
    congestion window and plateaus until no congestion is detected. It then
    increases the congestion window again.

- Explain TCP throughput calculation

  - Bandwidth (BW) is bound by ((Data and Time per Cycle Calculation) / (Round
    Trip Time (RTT))) \* 1 / sqrt(Probability of Packet Loss)
