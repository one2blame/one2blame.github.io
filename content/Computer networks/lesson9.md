---
title: Lesson 9
tags:
  - confidentiality
  - integrity
  - authentication
  - availability
  - dns
  - rrdns
  - bgp
  - cs6250
---

- What are the properties of secure communication?

  - Confidentiality
  - Integrity
  - Authentication
  - Availability

- How does Round Robin DNS (RRDNS) work?

  - Responding to a DNS request with a list of DNS A records, cycling through records each time.

- How does DNS-based content delivery work?

  - When a lookup is conducted for a resource / content, the delivery network will determine the
    best CDN server to service the request and use DNS to point the client to the right IP address.

- How do Fast-Flux Service Networks work?

  - Based on a rapid change in DNS answers, with a TTL lower than that of RRDNS and CDN. This is
    done in order to prevent spammers for injecting bad IP addresses into the DNS resolution
    lifecycle

- What are the main data sources to identify hosts that likely belong to rogue networks, used by
  FIRE (FInding Rogue nEtworks system)?

  - Botnet command and control providers
  - Drive-by-download hosting providers
  - Phish housing providers

- The design of ASwatch is based on monitoring global BGP routing activity to learn the control
  plane behavior of a network. Describe 2 phases of this system.

  1. Training phase - ASwatch learns the control-plane behavior of a normal AS and a malicious one
     and learns to differentiate between them.
  2. Operational phase - ASwatch takes an unknown AS and calculates the features for it, assigning
     it a reputation score.

- What are 3 classes of features used to determine the likelihood of a security breach within an
  organization?

  - Rewiring activity - changes in the AS connecting activity, multiple changes in providers /
    customers looks suspicious
  - IP Space Fragmentation and Churn - inspects advertised prefixes of an autonomous system.
    Malicious ASes are likely to use small BGP prefixes to partition their IP address space and only
    exposes a small section of them
  - BGP Routing Dynamics - tracks announcements and withdrawals, which usually follow different
    patterns for malicious ASes

- (BGP hijacking) What is the classification by affected prefix?

  - This classification is primarily concerned with the IP prefixes that are advertised by BGP.
    There are different ways the prefix can be targeted:
    - Exact prefix hijacking
    - Sub-prefix hijacking
    - Squatting

- (BGP hijacking) What is the classification by AS-Path announcement?

  - An illegitimate autonomous system announces the AS path for a prefix for which it doesn't have
    ownership rights.
    - Type-0 hijack - AS announcing a prefix not owned by itself
    - Type-N hijack - counterfeit AS announces an illegitimate path for a prefix that it does not
      own or create a fake path between different ASes
    - Type-U hijack - the hijacking AS does not modify the AS-PATH but may change the prefix

- (BGP hijacking) What is the classification by data plane traffic manipulation?

  - In this classification of attacks, the attacker attempts to hijack the network traffic and
    manipulate the redirected network traffic on its way to the receiving AS. Traffic intercepted
    can be:
    - Dropped (blackholing)
    - Man-in-the-middle
    - Impersonation

- What are the causes or motivations behind BGP attacks?

  - Human error - misconfiguration / accidents
  - Targeted attack - intentional interception of network traffic (man-in-the-middle) (stealthy)
  - High impact attack - obvious attempt to cause widespread disruption

- Explain the scenario of prefix hijacking.

  - Malicious autonomous system router advertises a prefix that it doesn't own, taking advantage of
    its shorter distance to have peer / customer routers change their path for the prefix to the
    malicious autonomous system.

- Explain the scenario of hijacking a path.

  - Malicious autonomous system receives a path and alters it, placing itself as the best path to
    reach a specific autonomous system / prefix. This path will likely be shorter than the original,
    causing other ASes to use the new hijacked path.

- What are the key ideas behind ARTEMIS?

  - A configuration file where all prefixes owned by the network are listed for reference.
  - A mechanism for receiving BGP updates, allows the system to receive updates from local routers
    and monitoring services

- What are the two automated techniques used by ARTEMIS to protect against BGP hijacking?

  - Prefix deaggregation - announcing more specific prefixes in order to mitigate prefix hijacking
  - Mitigation with multiple origin AS (MOAS) - third party organizations and service providers do
    BGP announcements for a given network

- What are two findings from ARTEMIS?

  1. Outsource the task of BGP announcements to third parties
  2. Filtering of prefixes is less optimal when compared against BGP announcements

- Explain the structure of a DDoS attack.

  - An attempt to compromise a server or network resources with a flood of traffic
  - Attack compromises and deploys flooding servers that send high volumes of traffic to a victim

- What is spoofing, and how is related to DDoS attack?

  - Impersonating a legitimate server with a spoofed IP address. One method causes a server to flood
    a target with unsolicited responses to spoofed requests. The other uses the spoofed IP address
    in the both the source and destination IP, causing the server to send responses / requests to
    itself.

- Describe a Reflection and Amplification attack.

  - A reflective attack is sending a bunch of spoofed requests to a server which will then DDoS the
    target on behalf of the attacker.

- What are the defenses against DDoS attacks?

  - Traffic Scrubbing Services
  - Access Control List filters
  - BGP Flowspec

- Explain provider-based blackholing.

  - A customer autonomous system announces a blackholing message to the provider with the host name
    of the DDoS victim. This usually contains a special community field - the provider will then
    stop advertising the prefix of the affected host.

- Explain IXP blackholing.

  - Same as the above, but on an autonomous system scale. The IXP will handling the blackholing and
    advertise the NULL address to the other ASes peered in the IXP.

- What is one of the major drawbacks of BGP blackholing?

  - The destination under attack becomes unreachable.
  - The mitigation technique is also ineffective if peer autonomous systems neglect / don't respect
    BGP Blackholing requests.
