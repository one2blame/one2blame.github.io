---
title: Internet architecture
tags:
  - isp
  - ixp
  - cdn
  - autonomous
  - system
  - bgp
  - border
  - gateway
  - protocol
  - cs6250
---

The following are questions and answers from the Exam 1 Study Guide for Lesson
4:

- Describe the relationships between ISPs, IXPs, and CDNs

  - ISPs (Internet Service Providers) are the “backbone” network over which
    smaller networks can connect. IXPs (Internet Exchange Points) are physical
    interconnection infrastructures that are used by multiple networks (such as
    ISPs and Content Distribution Networks (CDNs)) to interconnect.

  - CDNs are networks created by content providers (such as Shopify/Netflix) to
    reduce connectivity costs and provide greater control for the content
    provider on how the content is delivered to the end-users. They may have
    multiple data centers with hundreds of servers distributed across the world.

- What is an AS?

  - Autonomous System (AS) - a group of routers that operate under the same
    administrative authority. An ISP (or CDN) can operate as a single AS or
    multiple. Each AS has its own set of policies/strategies based on their
    needs and doesn’t need to share this info with other ASes.

- What kind of relationship does AS have with other parties?

  - Competition and cooperation. T1 ISPs compete with each other, T2 with each
    other, etc - there is a hierarchy but this hierarchy is becoming more flat
    over time thanks to evolutions such as IXPs and CDNs. Competing ISPs also
    need to cooperate so that the Internet can work on a global scale.

- What is BGP?

  - For traffic to go between ASes, BGP (Border Gateway Protocol) is used which
    is primarily based on incentives (money) - ASes do whatever makes the most
    sense for them from a financial standpoint.

- How does an AS determine what rules to import/export?

  - It's entirely a business decision for both importing and exporting routes.
    ASes are incentivized to advertise customer routes, peer routes none, and
    provider routes none. For importing routes from other ASes, ASes are
    incentivized to import customer routes most, peer routes less, and provider
    routes none.

- What are were original the design goals of BGP? What was considered later?

  - The original design goals were:

        * Scalability - quick convergence and loop-free pathing
        * Express routing policies - allow ASes to implement policies, filter and rank

    routes, and keep these decisions confidential \* Allowing cooperation among
    ASes - allows ASes to make local decisions while keeping these decisions
    confidential from other ASes

        * **Security** was not originally considered when implementing BGP, requiring

    security measures to be added later as the Internet grew in size and
    complexity.

- What are the basics of BGP?

  - A pair of routers, **BGP peers**, exchange routing info over a
    semi-permanent TCP port connection **(BGP session)**. This starts with an
    OPEN message and is followed by the routers sending each other announcements
    from their own routing tables.

  - There are two types of **BGP messages**:

    - **UPDATE** - announcements of new routes/updates to existing routes;
      withdrawal of previous routes due to a failure or change in routing policy
    - **KEEPALIVE** - message exchanged to keep a current session going

  - **BGP routes** - main components: reachable IP prefix field, AS-PATH (route
    passed through from destination), and NEXT-HOP (IP of next-hop router along
    the path towards the destination). In iBGP the NEXT-HOP is the address of
    the nearest border router.

- What is the difference between iBGP and eBGP?

  - **eBGP** - external BGP; BGP session between pair of routers in two
    different ASes
  - **iBGP** - internal BGP; BGP session between routers in the same AS

- What is the difference between iBGP and IGP-like protocols (RIP or OSPF)?

  - iBGP is used to propagate information about what ASes can be reached by the
    gateway routers in the current AS. IGP-like protocols are used to establish
    paths between the internal routers of an AS based on specific costs within
    the AS.

- How does a router use the BGP decision process to choose which routes to
  import?

  - The actual policies are based on the business goals of the AS, but they all
    follow the same process to select the best routes based on the policy in
    place. The router compares a list of attributes, between a pair of routes,
    in top down order - if two attributes are equal then it moves down to the
    next attribute and so on.
  - **LocalPref** is at the top and set by the local AS’ administrator based on
    business relationships/preference of specific AS. **Higher number = higher
    preference.** Controls which routers are used as exit points (outgoing
    traffic).
  - **MED** (Multi-Exit Discriminator) is another important attribute and is set
    by the neighboring ASes. **Lower MED value = higher preference.** A
    neighboring AS with multiple links can tag routes with MED values to
    indicate which routers are used as entry points (which links are preferred
    for inbound traffic).
  - LocalPref = outbound; MED = inbound

- What are 2 main challenges with BGP? Why?

  - Scalability and misconfigurations or faults. An error can result in an
    excessively large number of updates which can lead to route instability,
    overloading, outages, etc.
  - ASes can reduce this risk by limiting routing table size with filtering to
    encourage route aggregation and limiting the number of route changes with
    flap damping (suppresses route updates for a period of time when a threshold
    is reached which can be set individually for prefixes according to a
    specific strategy).

- What is an IXP?

  - **Internet Exchange Points** - physical infrastructures that provide the
    means for ASes to interconnect and directly exchange traffic with one
    another.

- What are four reasons for IXPs increased popularity?

  1. They can handle large traffic volumes comparable to T1 ISPs
  2. Play an important role in mitigating DDoS attacks as they can play the role
     of a “shield” such as with BGP blackholing
  3. Provide a plethora of research opportunities into the evolution of the
     Internet landscape
  4. Active marketplaces with many services beyond interconnection - they have
     been evolving from simple interconnection hubs to technology innovation
     hubs

  - Keeps traffic local when both on the same IXP, lower costs, incentives from
    big players.

- Which services do IXPs provide?

  1. Public peering
  2. Private peering (separate from public)
  3. Route servers and service level agreements (many participants on a network
     can use it with a single agreement/BGP session)
  4. Remote peering through resellers (third parties can resell their connection
     to IXP to networks that use less traffic/in distant area)
  5. Mobile peering
  6. DDoS blackholing (customer can trigger this to alleviate DDoS effects)
  7. Free value-added services such as nameservers, local time, DNS root name
     servers, etc.

- How does a route server work?

  - Route servers help to make peering more manageable. In summary, a Route
    Server (RS):

        * Collects and shares routing information from its peers or participants that

    connects with (i.e. IXP members that connect to the RS). \* Executes it’s
    own BGP decision process and also re-advertise the resulting information
    (I.e. best route selection) to all RS’s peer routers.

  - A typical routing daemon maintains a **Routing Information Base (RIB)**
    which contains all BGP paths that it receives from its peers - the Master
    RIB. The router server also maintains AS-specific RIBs to keep track of the
    individual BGP sessions they maintain with each participant AS.

  - RSes maintain two types of route filters:

        * **Import filters** are applied to ensure that each member AS only advertises

    routes that it should advertise \* **Export filters** which are typically
    triggered by the IXP members themselves to restrict the set of other IXP
    member ASes that receive their routes.
