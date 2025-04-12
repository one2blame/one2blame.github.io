---
title: Path algorithms
tags:
  - dijkstra
  - algorithm
  - forwarding
  - routing
  - ospf
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson 3:

- What is the difference between the forwarding and routing?

  - **Forwarding** - refers to transferring a packet from an incoming link to an outgoing link
    within a single router.
  - **Routing** - refers to how routers work together using routing protocols to determine the good
    paths (or good routes as we call them) over which the packets travel from the source to the
    destination node.

- What is the main idea behind a link state routing algorithm?

  - In a link state routing algorithm / protocol, link costs and the network topology are known to
    all nodes.
  - Based upon Djikstra's algorithm.
  - Start with N’ just containing the source node. Initialize all paths to infinity except directly
    attached nodes. Perform iterations and update whenever we find lower costs until every node is
    examined and added to N’.

- What is an example of a link state routing algorithm?

  - Open Shortest Path First (OSPF)

- Walk through an example of the link state routing algorithm

  - At each iteration, look among nodes not yet in N’, select the node with least cost from the
    previous iteration. Update distance for all immediate neighbors of this node using the lowest
    cost paths.

- What is the computational complexity of the link state routing algorithm?

  - O(n^2)

- What is the main idea behind distance vector routing algorithm?

  - Based upon the Bellman-Ford algorithm.
  - Iterative (continues until no more updates)
  - Asynchronous (nodes do not have to be synchronized with each other)
  - Distributed (no need to know network topology or have some central point of calculation)

- Walk through an example of the distance vector algorithm

  - Each node maintains its own distance vector with costs to reach every other node in the network.
    They send each other their distance vectors and update accordingly if there are shorter paths
    found between what was already in its distance vector and newly received information.

- When does count-to-infinity problem occur in the distance vector algorithm?

  - When a large change occurs across a link, causing an infinite number of updates to be propagated
    across nodes. This can continue to happen until the nodes' tables eventually converge. This can
    happen if nodes have large positive or negative numbers.

- How does poison reverse solve the count-to-infinity problem?

  - When one node knows there is a path through another node, it will poison the opposite path so it
    is never taken. When bad news comes, it will take the opposite path and pass on this information
    so the new path is quickly used and the previous path becomes poisoned. This solves the problem
    with 2 nodes but is not guaranteed to work for 3 or more nodes that are not directly connected.

- What is the Routing Information Protocol (RIP)?

  - Based on the Distance Vector protocol and uses hop count as the metric (each link = 1 cost).
    Uses RIP response message instead of distance vectors. Each node maintains a RIP Table (Routing
    Table), which will have one row for each subnet in the AS. Uses UDP.

- What is the Open Shortest Path First (OSPF) protocol?

  - A routing protocol that uses the link-state routing algorithm to find the best path between
    source and destination router. Advancement of RIP. Uses flooding of link-state info and
    Dijkstra. Advances include authentication of messages, option to use multiple same cost paths,
    and support for hierarchy within a single routing domain.

- How does a router process advertisements?

  - The router checks if advertisement is new or duplicate by referring to the link-state database.
    If its new, it updates this database and runs OSPF based on current topology. It floods the LS
    update and updates FIB.

- What is hot potato routing?

  - When there are equally good egress points (network exits) - choose the one that is the shortest
    (closest) path cost away.
