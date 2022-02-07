# 🏗👷🏾 Moodyeth

[![moodyeth](https://img.shields.io/pypi/v/moodyeth?style=plastic)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://img.shields.io/pypi/pyversions/moodyeth.svg)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://api.travis-ci.com/tokenchain/moodyeth.svg?branch=master)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://img.shields.io/github/issues/tokenchain/moodyeth.svg)](https://pypi.org/project/moodyeth/)


Ethereum based all Moody tool chain for smart contract development kit

### Install

`pip install moodyeth`

`python3 install moodyeth`


The development of Moody contract deployment tools:

Setup (for the early version, we are going to setup the workspace manually. )

Setup the folders:
 /vault
 /artifact
 /deploy_history
 /deploy_results
 /factoryabi

### Why use moody tool

It is a all-in-one package with zero setup and configurations that works for multiple architectures. Build-in ERC20 support and bulk token sending support.

### Features

- golang module compile support
- python module compile support
- typescript module compile support

### Deployment:

```
# !/usr/bin/env python
# coding: utf-8
import os

from moody.libeb import MiliDoS
from moody import conf
from key import pri

ROOT = os.path.join(os.path.dirname(__file__))
meta = MiliDoS(conf.XDaiMainnet()).withPOA()
meta.setWorkspace(ROOT).Auth(pri)
meta.deploy("Ori20")

```

# 🏗👷🏾 Scaffold-evm Challenges

> learn how to use 🏗 scaffold-eth to create decentralized applications on Ethereum. 🚀

---

## 🚩 Challenge 0: 🎟 Simple NFT Example 🤓

🎫 Create a simple NFT to learn basics of 🏗 scaffold-eth. You'll use 👷‍♀️ HardHat to compile and deploy smart contracts. Then, you'll use a template React app full of important Ethereum components and hooks. Finally, you'll deploy an NFT to a public network to share with friends! 🚀



---

## 🚩 Challenge 1: 🥩 Decentralized Staking App

🦸 A superpower of Ethereum is allowing you, the builder, to create a simple set of rules that an adversarial group of players can use to work together. In this challenge, you create a decentralized application where users can coordinate a group funding effort. If the users cooperate, the money is collected in a second smart contract. If they defect, the worst that can happen is everyone gets their money back. The users only have to trust the code.


---

## 🚩 Challenge 2: 🏵 Token Vendor 🤖

🤖 Smart contracts are kind of like "always on" vending machines that anyone can access. Let's make a decentralized, digital currency. Then, let's build an unstoppable vending machine that will buy and sell the currency. We'll learn about the "approve" pattern for ERC20s and how contract to contract interactions work.


---


### Donations

Welcome for donation for the good works!