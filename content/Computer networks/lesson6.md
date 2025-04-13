---
title: Firewalls
tags:
  - firewalls
  - traffic
  - scheduling
  - round
  - robin
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson
6:

- Why is packet classification needed?

  - **Packet classification** is needed to accomplish quality of service
    guarantees and security guarantees that longest prefix matching based on
    destination IP alone cannot do. This allows handling packets based on other
    criteria such as TCP flags and source addresses.

- What are three established variants of packet classification?

  1. **Firewalls** - filter out unwanted traffic and enforce other security
     policies
  2. **Resource reservation protocols** - used to reserve bandwidth between
     source and destination
  3. **Routing based on traffic type** - used to avoid delays for time-sensitive
     applications

- What are the simple solutions to the packet classification problem?

  - **Linear search** - reasonable for a few rules (such as in a firewall) but
    otherwise inefficient.
  - **Caching** - cache the results so that future searches can run faster.
  - **Passing labels** - done in the header and typically at the edges which
    saves time.

- How does fast searching using set-pruning tries work?

  - Build a trie on destination prefixes and then at every leaf-node we “hang”
    the source tries that are compatible (or whatever other dimension we are
    considering for packet classification). To match a prefix, we first traverse
    the destination trie and then the source trie while keeping track of the
    lowest-cost matching rule.

- What’s the main problem with the set pruning tries?

  - Memory explosion - a source prefix can occur in multiple destination tries

- What is the difference between the pruning approach and backtracking approach
  for packet classification with a trie?

  - Set pruning has a high cost in memory with a lower cost in time.
    Backtracking saves memory but costs more in time. Each rule is only stored
    once.

- What’s the benefit of grid of tries approach?

  - It is a middle-ground approach that balances the memory and time costs by
    using precomputation with switch pointers. These are basically shortcuts.

- Describe the “Take the Ticket” algorithm

  - Each output line maintains a distributed queue for all input lines that want
    to send packets to it. When an input line wants to send a packet to a
    specific output line, it requests a ticket. The input line waits for the
    ticket to be served. At that point, the input line connects to the output
    line, the crosspoint is turned on, and the input line sends the packet.

- What is head-of-line problem?

  - The other lines are stuck in the line waiting for their turn - the entire
    queue is blocked by the progress of the head of the queue.

- How to avoid head-of-line problem using knockout scheme?

  - Break up the packets into a fixed size (cell). Have the fabric running N
    times faster than the input links where k is the expected number of cells
    received by an output link. For cases where the expectation is violated,
    randomly pick the output that is chosen. Complex to implement.

- How to avoid head-of-line problem using parallel iterative matching?

  - All inputs send requests in parallel to all outputs they want to connect
    with. This is the request phase. In the grant phase, the outputs randomly
    pick an input out of its requestors. In the accept phase, inputs randomly
    pick an output to send to. This way, all of the inputs are sending packets
    from the start.

- Describe FIFO with tail drop

  - Packets are sent to the output ports. The output ports are FIFO and any
    packets that overflow the buffer (tail of the queue) are dropped. This
    results in fast scheduling decisions but loss of packets.

- What are the reasons to make scheduling decisions more complex than FIFO?

  - To provide quality of service (QoS) guarantees on measures such as delay and
    bandwidth. To provide additional (router) support for congestion. To promote
    fair sharing of links among competing flows.

- Describe Bit-by-bit round Robin scheduling

  - Gives bandwidth and delay guarantees. We calculate the packet finishing time
    for each packet and send the packet with the smallest finishing round number
    based on the previous round of the algorithm.

- Bit-by-bit Round Robin provides fairness, what’s the problem with this method?

  - Requires introducing extra time complexities such as keeping track of the
    finishing time (requires priority queue). The extra complexities make it
    hard to implement at gigabit speeds.

- Describe Deficit Round Robin (DRR)

  - Solves some of the time complexities of bit-by-bit round robin by using a
    deficit counter instead of performing all the calculations of finishing
    time. This ensures fairness.

- What is a token bucket shaping?

  - Used for the scenarios where we want bandwidth guarantees for flows in the
    same queue without separating them. Limits the burstiness of a flow by
    limiting the average rate and limiting the maximum burst size. The technique
    assumes a bucket per flow that fills with tokens at a rate R per second with
    a max of B tokens. Additional tokens are dropped. When packets arrive, they
    can go through if there are enough tokens, otherwise it must wait for more
    tokens to fill the bucket.

- In traffic scheduling, what is the difference between policing and shaping?

  - **Policing** is a modified version of token bucket shaping - when a packet
    arrives it needs to have tokens at the bucket already there. If the bucket
    is empty, the packet is dropped.

  - Policing - sawtooth wave pattern.
  - Shaper - keeps excess in a queue or buffer so traffic is delayed instead of
    dropped. Smooth/shaped curve instead of sawtooth.

- How is a leaky bucket used for traffic policing and shaping?

  - Similar to a bucket with a hole - constant flow of network traffic out of
    the bucket where the bucket can be seen as the buffer, water represents
    packets, and the leak rate is the rate at which packets are allowed to enter
    the network. If the packet will not cause overflow to the bucket, the packet
    is added (conforming) to the bucket. Otherwise it is discarded
    (non-conforming).

  - Irrespective of the input rate of packets, the output rate is constant which
    leads to uniform distribution of packets sent to the network.
