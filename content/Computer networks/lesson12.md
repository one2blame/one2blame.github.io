---
title: Lesson 12
tags:
  - content
  - distribution
  - network
  - cs6250
---

- What is the drawback to using the traditional approach of having a single,
  publicly accessible web server?

  1. Users are located all across the globe, interruptions for geographically
     separated users can be prevalent
  2. Viral videos will cause the server to be overloaded
  3. Single point of failure in the case of a natural disaster

- What is a CDN?

  - Content Distribution Network - networks of multiple, geographically
    distributed servers and/or data centers with copies of content that direct
    users to a server or server cluster that can best serve the user's request.

- What are the six major challenges that Internet applications face?

  1. Peering point congestion
  2. Inefficient routing protocols
  3. Unreliable networks
  4. Inefficient communication protocols
  5. Scalability
  6. Application limitations and slow rate of change adoption

- What are the major shifts that have impacted the evolution of the Internet
  ecosystem?

  1. Increased demand for online content, especially videos
  2. Topological flattening of the Internet

- Compare the “enter deep” and “bring home” approach of CDN server placement.

  - Enter deep - phrase used to describe placing CDNs deep into the access
    networks of the world. Makes the distance between the user and the closest
    server cluster as small as possible. Downside is that it's difficult to
    manage and maintain so many clusters.
  - Bring home - place fewer, larger clusters at key points - less servers to
    maintain but the users will experience higher delay and lower throughput

- What is the role of DNS in the way CDN operates?

  - DNS servers will consult local DNS servers for the ISP / CDN and determine
    the CDN that contains the requested video. The DNS will proceed to provide
    the client with the IP address of the CDN cluster / server containing their
    requested content.

- What are the two main steps in CDN server selection?

  1. Mapping the client to a cluster
  2. Selecting a server from the cluster

- What is the simplest approach to select a cluster? What are the limitations
  of this approach?

  - Selecting the geographically closest cluster
  - Selecting the geographically closest cluster is actually picking the
    closest cluster to the LDNS which might not be the closest to the client.
  - The closest cluster might not have the best performance either.

- What metrics are could be considered when using measurements to select a
  cluster?

  - The end-to-end metrics to be considered for cluster selection are delay and
    bandwidth.

- How are the metrics for cluster selection obtained?

  - Active metric collection through probing, pinging.
  - Passive metric collection to track network conditions.

- Explain the distributed system that uses a 2-layered system. What are the
  challenges of this system?

  - The cluster selection strategy proposes requires a centralized controller
    that has a real-time view of the network conditions - difficult to do given
    the scale of today's networks.
  - This model also needs to have data for different subnet-cluster pairs. Some
    clients will be deliberately routed to sub-optimal clusters.

- What are the strategies for server selection? What are the limitations of
  these strategies?

  - A server could be assigned randomly. Not optimal because a highly stressed
    server could be selected randomly.
  - Load balancing could be used, but also not optimal

- What is consistent hashing? How does it work?

  - Distributed hash table used to balance load, assigning roughly the same
    number of content IDs and requires relatively little movement of these
    content IDs when nodes join and leave the system.

- Why would a centralized design with a single DNS server not work?

  - Introduces a single point of failure

- What are the main steps that a host takes to use DNS?

  1. The user host runs the client side of the DNS application
  2. The browser extracts the hostname and passes it to the client side of the
     DNS application
  3. DNS Client sends a query containing the hostname of DNS
  4. DNS Client eventually receives a reply which includes the IP address of
     the hostname
  5. As soon as the host receives the IP address, it can initiate a TCP
     connection to the HTTP server located at that IP

- What are the services offered by DNS, apart from hostname resolution?

  1. Mail server / host aliasing
  2. Load distribution

- What is the structure of DNS hierarchy? Why does DNS use a hierarchical
  scheme?

  - The DNS hierarchy solves the scalability problem.
  - THe hierarchy has root servers, top level domain servers, authoritative
    servers, and local DNS servers.

- What is the difference between iterative and recursive DNS queries?

  - Iterative - the client is referred to a different DNS server in the chain
    until it can resolve the request
  - Recursive - each DNS server will resolve the hostname on behalf of the
    client, client doesn't have to submit more than one request

- What is DNS caching?

  - Saving hostname resolutions locally

- What is a DNS resource record?

  - A method of storing the hostname to IP address resolution

- What are the most common types of resource records?

  - Type A - domain name and IP address
  - Type NS - domain name and appropriate authoritative DNS server
  - Type CNAME - alias hostname and canonical name
  - Type MX - alias hostname of a mail server and the canonical name of the
    mail server

- Describe the DNS message format.
- What is IP Anycast?

  - Route a client to the closest server as determined by BGP. Assigns the same
    IP address to multiple servers and lets BGP handle getting the client to
    the closest server.

- What is HTTP Redirection?

  - Just sending a client a 300-level code to request the content from a
    different server. Useful for load balancing, doesn't require central
    coordination.
