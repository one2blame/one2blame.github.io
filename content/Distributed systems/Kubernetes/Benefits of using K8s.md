---
tags:
  - kubernetes
  - distributed
  - cloud
  - system
  - systems
  - k8s
  - benefits
title: Benefits of using K8s
---

We'll discuss the benefits and values of using **Kubernetes (K8s)** for the
design and implementation of your distributed system. At a high level, K8s
provides the following for engineers:

- Development velocity
- Scaling
- Abstraction
- Efficiency
- Cloud nativity

## Velocity

K8s allows you to iterate and ship applications faster in a reliable manner. The
core concepts of K8s that enable its velocity are:

- Immutability
- Declarative configuration
- Self-healing systems
- Shared libraries and tools

### Immutability

K8s units of work are container images, and K8s deploys these container images
from a container registry. These containers are configured, built, recorded, and
pushed to a registry for consumption. If application updates need to be made,
they happen declaratively during the container build instead of live, while the
system is online.

This process creates a record, allowing developers to see the differences
between an old version of a container and a new one. If failures occur with the
updated application in the new container, it's easy to rollback to a previously
working container.

### Declarative configuration

Everything in Kubernetes is a **declarative configuration**. Kubernetes ensures
that the state of the world matches the desired state. GitOps is a process that
formalises the practise of infrastructure as code and declarative configuration,
using repositories as the source of truth for the state of a system. When
changes are pushed to a repository, these changes are reflected in K8s.

### Self-healing systems

K8s continuously takes actions to **self-heal**, making sure that the desired,
declared state is reflected in reality. If the declared state calls for three
container nodes to exist and one crashes, K8s will recover and deploy a third
node.

For more complex actions, K8s has the concept of **operator** container nodes
that engineers can configure to take specialised actions for advanced health
detection and healing.

## Scaling

K8s allows you to scale your software and teams. This is accomplished by the
amount of decoupling and abstraction present in the K8s ecosystem. The following
abstractions in K8s enable this feature:

- Pods - a grouping of container images developed by different teams in to a
  single deploy-able unit
- Services - services provided by K8s that provide load balancing, naming, and
  discovery to provide isolation between microservices
- Namespaces - provide isolation and access control, controlling the degree to
  which other services can interact with it
- Ingress - objects that provide a frontend, combining multiple microservices
  into a single API surface area

## Abstraction

Cloud providers' unit of work is a virtual machine, whereas developers are more
concerned with the application and its consumption. Additionally, cloud
providers each have their own mechanism for configuring and deploying cloud
resources, making portability between clouds difficult.

When developers build applications in terms of container images and deploy them
using K8s APIs, transferring applications between clouds becomes much simpler,
and you can ignore the environment you're deploying to - whether it be Amazon
Web Services, Azure, or Google Cloud Platform.

Developers can even use features like K8s PersistentVolumes and
PersistentVolumeClaims to abstract applications away from specific storage
implementations in each cloud.
