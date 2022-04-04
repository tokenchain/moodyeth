#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import List

from . import conf, Key, Config
from .libeb import MiliDoS
from .m.b_send import BSend


class BusExpress(MiliDoS):
    """
    Application for MiliDoS that allows sender to setup their own contract in python
    """

    def __init__(self, _nodeCfg: Config):
        super().__init__(_nodeCfg)
        self.kol = None
        self.ContractBusExpress: BSend = None

    def start(self, privat_key: str, rootpath: str) -> "BusExpress":
        super().__init__(conf.XDaiMainnet())
        self.Auth(privat_key).connect(rootpath, "xDaiBusSend")
        self.OverrideGasConfig(2000000000, 6000000)
        self.ready_io(True)
        return self

    @property
    def BSendAddress(self) -> str:
        if "BSend" in self._contract_dict:
            return self.getAddr("BSend")
        else:
            raise ValueError("not BSend contract address is found")

    def SetupContract(self) -> "BusExpress":
        self.ContractBusExpress = BSend(self, self.BSendAddress) \
            .CallDebug(True) \
            .EnforceTxReceipt(False)
        # self.MasterContract = ERC20(self.w3, self.BSendAddress).CallDebug(False).CallContractFee(10000000)
        return self

    def AddAdmin(self, address: str) -> "BusExpress":
        self.ContractBusExpress.add_signer(address)
        return self

    def Error(self, str_s: str) -> None:
        print(f"Error: {str_s}")

    def ListSend(self, token: str, addresses: List[str], amounts: List[int]) -> "BusExpress":

        if len(addresses) > 256 or len(amounts) > 256:
            self.Error("items are over 256")
            return self

        if len(addresses) != len(amounts):
            self.Error("items are not balanced")
            return self

        self.ContractBusExpress.EnforceTxReceipt(False).bulk_send_token(token, addresses, amounts)
        return self
