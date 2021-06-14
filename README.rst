======================================
Ether API for Python The only Library
======================================

A Python API for interacting with the Ether (ETH)

.. image:: https://img.shields.io/pypi/v/moodyeth.svg
    :target: https://pypi.python.org/pypi/moodyeth

.. image:: https://img.shields.io/pypi/pyversions/moodyeth.svg
    :target: https://pypi.python.org/pypi/moodyeth

.. image:: https://api.travis-ci.com/tokenchain/moodyeth.svg?branch=master
    :target: https://travis-ci.com/tokenchain/moodyeth
    
.. image:: https://img.shields.io/github/issues/tokenchain/moodyeth.svg
    :target: https://github.com/tokenchain/moodyeth/issues
    
.. image:: https://img.shields.io/github/issues-pr/tokenchain/moodyeth.svg
    :target: https://github.com/tokenchain/moodyeth/pulls


------------

**A Command-Line Interface framework**

You can install it in a system-wide location via pip:

.. code-block:: bash

    sudo pip3 install moodyeth

Or install it locally using `virtualenv <https://github.com/pypa/virtualenv>`__:

.. code-block:: bash

    virtualenv -p /usr/bin/python3 ~/moodyeth
    source ~/moodyeth/bin/activate
    pip3 install moodyeth

------------

Usage
=====
Specify the API endpoints:

Deploy Smart Contract
---------------------

.. code-block:: python

    import os

    from moody.libeb import MiliDoS
    from moody import conf
    from key import pri

    ROOT = os.path.join(os.path.dirname(__file__))
    c = MiliDoS(conf.MoonBeamTestnet())
    c.setWorkspace(ROOT).Auth(pri).withPOA()
    c.deploy("ERC20")



Documentation
=============
Read the library manual by the `manual <docs/moody/index.html>`__
Documentation is available at `docs <https://moodyeth.readthedocs.io/en/latest/>`__.


Donations
=============

Welcome for donation for the good works!
