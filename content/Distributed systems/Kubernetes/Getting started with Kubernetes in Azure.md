---
tags:
  - kubernetes
  - k8s
  - cloud
  - distributed
  - systems
  - system
  - azure
  - powershell
title: Getting started with Kubernetes in Azure
---

This page discusses getting a **Kubernetes (K8s) cluster** online **Azure**.
First, get a Microsoft account and login to [Azure](https://portal.azure.com).
This guide is tailored for Linux. If you're on Windows, read the documentation
provided by Microsoft for this scenario.

## Installing PowerShell

I'm on **Kali Linux**, so installing PowerShell is as easy as invoking:

```bash
sudo apt-get install powershell --yes
```

It's probably the same on Ubuntu or any other Debian Linux distribution. Once
you have PowerShell installed, invoke it with `pwsh`.

### Install Az

The **Az** PowerShell module is _the_ PowerShell module to interact with Azure.
To install it, invoke the following in a PowerShell session:

```powershell
Install-Module -Name Az -Repository PSGallery -Force
```

## Connecting to Azure

Connect your PowerShell session to Azure by invoking the following:

```powershell
Import-Module Az.Accounts
Connect-AzAccount
```

This will open your system's default browser and prompt you to login. After
successfully logging into Azure, make sure you've selected your desired Azure
Subscription by invoking:

```powershell
Get-AzContext
```

## Creating a Kubernetes cluster

Invoke the following in order to create a new Azure Resource Group and
Kubernetes cluster:

```powershell
New-AzResourceGroup -Name $ResourceGroupName -Location westus

New-AzAksCluster `
	-ResourceGroupName $ResourceGroupName `
	-Name $ClusterName `
	-GenerateSshKey
```

The above commands will create a new Azure Resource Group and Azure Kubernetes
Services cluster in your subscription. To connect to and interact with the
cluster, invoke the following:

```powershell
Install-AzAksCliTool

Import-AzAksCredential `
	-ResourceGroupName $ResourceGroupName `
	-Name $ClusterName
```

The `kubectl` binary will be saved to your disk in the current directory with
the path `.azure-kubectl`. Add this path to your environment's `PATH` and mark
the `kubectl` binary in this directory as executable.

Once you've done the above, invoke `kubectl` and get the status of your cluster
with the following:

```powershell
kubectl get nodes
```
