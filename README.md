# 🏗👷🏾 Moodyeth
### Ether API for Python The only Library

[![moodyeth](https://img.shields.io/pypi/v/moodyeth?style=plastic)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://img.shields.io/pypi/pyversions/moodyeth.svg)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://api.travis-ci.com/tokenchain/moodyeth.svg?branch=master)](https://pypi.org/project/moodyeth/)
[![moodyeth](https://img.shields.io/github/issues/tokenchain/moodyeth.svg)](https://pypi.org/project/moodyeth/)


Ethereum based all Moody tool chain for smart contract development kit [documentation](https://htmlpreview.github.io/?https://github.com/tokenchain/moodyeth/blob/main/docs/moody/index.html).

### Why do we use python
Using it because it is fast and easy. More importantly it runs directly by its own and no more dependencies.

Its much faster to building modules and calling functions on python.
Also it can be wrapped into an executable binary on wasm or cpython that runs on natively any platforms.

If you are using PyCharm or similar IDE, all type are ready to show at your finger tips.

### Get Started

`pip3 install moodyeth`

or upgrade using

`sudo pip3 install moodyeth --upgrade`

or try this without vpn

`sudo pip3 install moodyeth --upgrade -i https://pypi.tuna.tsinghua.edu.cn/simple`

`sudo pip3 install moodyeth --upgrade -i https://pypi.python.org/simple`

The development of Moody contract deployment tools:

Setup (for the early version, we are going to setup the workspace manually. )

Setup the folders:
 /vault
 /artifact
 /deploy_history
 /deploy_results
 /factoryabi

### Why use moody eth

It is a all-in-one package with zero setup and configurations that works for multiple architectures. It is lightweight and simple. Build-in ERC20 support and bulk token sending support. Out of the box that comes with solc-compile automation and web3 executions.

### Features
- support most of the evm compatible chains
- golang module compile support
- python module compile support
- typescript module compile support

### Examples:

##### Deployment of the new contract:

```
# !/usr/bin/env python
# coding: utf-8
import os

from moody.libeb import MiliDoS
from moody import conf

privatekey = "xxxxxxxx"
# now using xDAI
network = conf.XDaiMainnet()

ROOT = os.path.join(os.path.dirname(__file__))
meta = MiliDoS(network).withPOA()
meta.setWorkspace(ROOT).Auth(privatekey)
meta.deploy("Ori20")

```

#### BSend add signer
Adding signer using bsend
```
# !/usr/bin/env python
# coding: utf-8
import os

from moody.libeb import MiliDoS
from moody import conf

privatekey = "xxxxxxxx"
# now using xDAI
network = conf.XDaiMainnet()

#gas and gas price configurations
meta.OverrideGasConfig(6000000, 2000000000)

ROOT = os.path.join(os.path.dirname(__file__))
meta = MiliDoS(network).withPOA().setWorkspace(ROOT).Auth(privatekey)

contract_address = "0x_________________"

signing_address =  "0x________my_wallet"

expressContract = BSend(meta, contract_address).CallAutoConf(meta).CallDebug(True)

expressContract.add_signer(signing_address)

```

#### Mint Coins
The example for minting coins with 18 decimal

```
# !/usr/bin/env python
# coding: utf-8
import os

from moody.libeb import MiliDoS
from moody import conf
from moody.m.tc20 import Tc20

privatekey = "xxxxxxxx"
contract_address = "0x_________________"
my_wallet =  "0x________my_wallet"

# now using xDAI
network = conf.XDaiMainnet()

#gas and gas price configurations
meta.OverrideGasConfig(6000000, 2000000000)

ROOT = os.path.join(os.path.dirname(__file__))
meta = MiliDoS(network).withPOA().setWorkspace(ROOT).Auth(privatekey)


tokenContract = Tc20(meta, contract_address).CallAutoConf(meta)

# assume this coin comes with 18 decimal
tokenContract.EnforceTxReceipt(True).mint(my_wallet, 300*10**18)

```

Documentation is ready [here](https://htmlpreview.github.io/?https://github.com/tokenchain/moodyeth/blob/main/docs/moody/index.html)

Also there is a brother library for those who works with [Tron](https://github.com/tokenchain/tronpytool) network.

# 📦 Showcase your project with this SDK
PR your link or your github repo here.



## Scaffold-evm Challenges

> learn how to use 🏗 scaffold-eth to create decentralized applications on Ethereum. 🚀

---

### 🚩 Challenge 0: 🎟 Simple NFT Example 🤓

🎫 Create a simple NFT to learn basics of 🏗 scaffold-eth. You'll use 👷‍♀️ HardHat to compile and deploy smart contracts. Then, you'll use a template React app full of important Ethereum components and hooks. Finally, you'll deploy an NFT to a public network to share with friends! 🚀


---

### 🚩 Challenge 1: 🥩 Decentralized Staking App

🦸 A superpower of Ethereum is allowing you, the builder, to create a simple set of rules that an adversarial group of players can use to work together. In this challenge, you create a decentralized application where users can coordinate a group funding effort. If the users cooperate, the money is collected in a second smart contract. If they defect, the worst that can happen is everyone gets their money back. The users only have to trust the code.


---

### 🚩 Challenge 2: 🏵 Token Vendor 🤖

🤖 Smart contracts are kind of like "always on" vending machines that anyone can access. Let's make a decentralized, digital currency. Then, let's build an unstoppable vending machine that will buy and sell the currency. We'll learn about the "approve" pattern for ERC20s and how contract to contract interactions work.


---


### Donations

Welcome for donation for the good works!