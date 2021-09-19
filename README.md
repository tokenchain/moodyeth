# Moodyeth

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

### Contract testing setup:



### Donations

Welcome for donation for the good works!