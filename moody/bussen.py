#!/usr/bin/env python
# -*- coding: utf-8 -*-

from moody import conf
from moody.libeb import MiliDoS
from moody.m.b_send import BSend

from keyh import Key
from key import ROOT


class BusExpress(MiliDoS):
    """
    Application for MiliDoS that allows sender to setup their own contract in python
    """

    def __init__(self):
        self.kol = None

    def start(self, holder: Key) -> "BusExpress":
        super().__init__(conf.XDaiMainnet())
        self.Auth(holder.private_key).connect(ROOT, "xDaiBusSend")
        self.ready_io(True)
        return self

    @property
    def BSendAddress(self) -> str:
        if "BSend" in self._contract_dict:
            return self.getAddr("BSend")
        else:
            raise ValueError("not BSend contract address is found")

    def SetupContract(self) -> "BusExpress":
        self.ContractBusExpress = BSend(self.w3, self.BSendAddress).CallDebug(False).CallContractFee(100000000000000000)
        # self.MasterContract = ERC20(self.w3, self.BSendAddress).CallDebug(False).CallContractFee(10000000)
        return self

    def AddAdmin(self, address: str) -> "BusExpress":
        self.ContractBusExpress.add_whitelist_admin(address)
        return self
