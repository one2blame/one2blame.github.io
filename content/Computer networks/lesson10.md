---
title: Lesson 10
tags:
  - cs6250
  - dns
  - security
  - injection
  - censorship
  - great
  - firewalls
  - china
  - poisoning
---

- What is DNS censorship?

  - Large scale network traffic filtering strategy opted by a network to
    enforce control and censorship over Internet infrastructure to suppress
    material which they deem as objectionable.

- What are the properties of GFW (Great Firewall of China)?

  1. Locality of GFW nodes - majority view is that GFW censorship nodes are
     present at the edge.
  2. Centralized management - blocklists obtained from two distinct GFW
     locations show a high possibility of a central GFW management entity that
     orchestrates blocklists.
  3. Load balancing - GFW load balances between processes based on source and
     destination IP address.

- How does DNS injection work?

  - For DNS requests that are blocked by the GFW, the GFW will respond with a
    fake DNS record to prevent the client from reaching the requested content.

- What are the three steps involved in DNS injection?

  - DNS probe is sent to a DNS resolver
  - THe probe is checked against the blocklist
  - A fake DNS A record response is sent back if the request matches the
    blocklist. The direct domain can be blocked, or specific domain keywords
    can be blocked.

- List five DNS censorship techniques and briefly describe their working
  principles.

  1. Packet dropping - all traffic to specific IP addresses are dropped
  2. DNS Poisoning - return no answer or return an incorrect answer
  3. Content inspection - all traffic traverses a proxy and is inspected for
     objectionable content, if matches -> dropped
  4. Blocking with resets - sends a TCP (RST) to block individual connections
     that contain requests with objectionable content.
  5. Immediate reset - suspends traffic coming from a source immediately, for a
     short period of time

- Which DNS censorship technique is susceptible to overblocking?

  - Packet dropping

- What are the strengths and weaknesses of “packet dropping” DNS censorship
  technique?

  - Strengths
    - Easy to implement
    - Low cost
  - Weaknesses
    - Maintenance of the blocklist
    - Overblocking

- What are the strengths and weaknesses of “DNS poisoning” DNS censorship
  technique?

  - Strengths
    - No overblocking

- What are the strengths and weaknesses of “content inspection” DNS censorship
  technique?

  - Strengths
    - Precise censorship
    - Flexible
  - Weaknesses
    - Not scalable

- What are the strengths and weaknesses of “blocking with resets” DNS
  censorship technique?

  - None given.

- What are the strengths and weaknesses of “immediate reset of connections” DNS
  censorship technique?

  - None given.

- Our understanding of censorship around the world is relatively limited. Why
  is it the case? What are the challenges?

  1. Diverse measurements
  2. Need for scale
  3. Identifying the intent to restrict content access
  4. Ethics and minimizing risks

- What are the limitations of main censorship detection systems?

  - They either no longer exist or rely upon volunteers performing
    measurements, which can cause them to get in trouble with their local
    governments.

- What kind of disruptions does Augur focus on identifying?

  - This system focuses on IP-based disruptions, not DNS-based manipulations.

- How does Iris counter the issue of lack of diversity while studying DNS
  manipulation? What are the steps associated with the proposed process?

  - Iris uses open DNS resolvers located all over the globe.
  - The two main steps are:
    1. Scanning the Internet's IPv4 space for open DNS resolvers
    2. Identifying infrastructure DNS resolvers

- What are the steps involved in the global measurement process using DNS
  resolvers?

  1. Perform global DNS queries
  2. Annotating DNS responses with auxiliary information
  3. Additional PTR and TLS scanning

- What metrics does Iris use to identify DNS manipulation once data annotation
  is complete? Describe the metrics. Under what condition, do we declare the
  response as being manipulated?

  1. Consistency metrics
  2. Independent verifiability metrics

  - If neither of these metrics are satisfied, the response is said to be
    manipulated.

- How to identify DNS manipulation via machine learning with Iris?

  - Not covered.

- How is it possible to achieve connectivity disruption using routing
  disruption approach?

  - Withdrawing previously advertised prefixes using BGP

- How is it possible to achieve connectivity disruption using packet filtering
  approach?

  - Block packets meeting a certain criteria disrupting the normal forwarding
    action.

- Explain a scenario of connectivity disruption detection in case when no
  filtering occurs.

  - When no filtering occurs, the measurement machine will see an increase of 2
    in the IP ID - this means the two hosts communicated

- Explain a scenario of connectivity disruption detection in case of the
  inbound blocking.

  - Traffic from the reflector to the site containing objectionable data is
    blocked. Thus, the IP ID only increases by 1 because the SYN-ACK from the
    site never reaches the reflector.

- Explain a scenario of connectivity disruption detection in case of the
  outbound blocking.

  - Outbound reset packets from the reflector do not reach the site. The site
    will continue to send SYN-ACK packets until it receives an ACK, causing the
    reflector's IP ID to increase by 2 each time.
