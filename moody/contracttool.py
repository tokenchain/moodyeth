#!/usr/bin/env python
# coding: utf-8
from typing import Tuple

from . import Config, Bolors
from .libeb import MiliDoS


class ContractTool(MiliDoS):
    classes = [
        "Genesis", "Mine", "PriceOracle", "USDT", "Currency"
    ]

    def __init__(self, netconfig: Config, root_path, deploy_list: dict, wallet_addresses: list):
        self.ROOT = root_path
        self.wallet_addresses = wallet_addresses
        self.deploy_list = deploy_list
        super().__init__(netconfig)

    def referrer(self, w_index: int) -> str:
        return self.wallet_addresses[w_index][0]

    def referGene(self) -> str:
        if "GenesisKey" in self.deploy_list:
            return self.deploy_list["GenesisKey"]
        else:
            return self.GenesisKeyAddress

    def auth(self, w_index: int) -> Tuple[str, str]:
        return self.wallet_addresses[w_index][0], self.wallet_addresses[w_index][1]

    def ClassList(self, setup_list: list) -> "ContractTool":
        self.classes = setup_list
        return self

    def check_fill(self, inset: dict, cls_name: str) -> None:
        if len(inset) > 0:
            if cls_name not in self._contract_dict:
                print(f"Check class name: {Bolors.WARNING}{cls_name}{Bolors.RESET}")
                self._contract_dict[cls_name] = inset[cls_name]

    def FillAddresses(self, deploy_list_input: dict) -> "ContractTool":
        if len(self.deploy_list) == 0 or len(deploy_list_input) == 0:
            print(f"{Bolors.FAIL}deploy list not found {Bolors.RESET}")
            return self
        listuage = []

        if len(self.deploy_list) == 0:
            listuage = deploy_list_input

        elif len(deploy_list_input) == 0:
            listuage = self.deploy_list

        if len(listuage) == 0:
            print(f"{Bolors.FAIL}deploy list still not found {Bolors.RESET}")
            return self

        for m in [*self.classes]:
            self.check_fill(listuage, m)
        self.SaveConfig()

        return self

    @property
    def GenesisAddress(self) -> str:
        if "Genesis" in self._contract_dict:
            return self.getAddr("Genesis")
        else:
            raise ValueError(f"{Bolors.FAIL}not Genesis contract address is found {Bolors.RESET}")

    @property
    def GenesisKeyAddress(self) -> str:
        if "GenesisKey" in self._contract_dict:
            return self.getAddr("GenesisKey")
        else:
            raise ValueError(f"{Bolors.FAIL}not GenesisKey {Bolors.RESET}address is found")

    @property
    def TokenCurrencyAddress(self) -> str:
        if "Currency" in self._contract_dict:
            return self.getAddr("Currency")
        else:
            self.SaveConfig()
            return self.getAddr("Currency")

    @property
    def OracleAddress(self) -> str:
        if "PriceOracle" in self._contract_dict:
            return self.getAddr("PriceOracle")
        else:
            self.SaveConfig()
            return self.getAddr("PriceOracle")

    @property
    def MarkSixAddress(self) -> str:
        if "MarkSix" in self._contract_dict:
            return self.getAddr("MarkSix")
        else:
            raise ValueError("not MarkSix contract address is found")

    @property
    def ReferralNetworkAddress(self) -> str:
        if "ReferralNetwork" in self._contract_dict:
            return self.getAddr("ReferralNetwork")
        else:
            raise ValueError("not ReferralNetwork contract address is found")

    @property
    def ReferralColaAddress(self) -> str:
        if "ReferralCola" in self._contract_dict:
            return self.getAddr("ReferralCola")
        else:
            raise ValueError("not ReferralCola contract address is found")

    @property
    def FarmAddress(self) -> str:
        if "Farm" in self._contract_dict:
            return self.getAddr("Farm")
        else:
            raise ValueError("not Farm contract address is found")

    @property
    def TokenMineAddress(self) -> str:
        if "Mine" in self._contract_dict:
            return self.getAddr("Mine")
        else:
            raise ValueError("not Mine contract address is found")

    @property
    def USDTAddress(self) -> str:
        if "USDT" in self._contract_dict:
            return self.getAddr("USDT")
        else:
            raise ValueError("not USDT contract address is found")

    @property
    def USDCAddress(self) -> str:
        if "USDC" in self._contract_dict:
            return self.getAddr("USDC")
        else:
            raise ValueError("not USDC contract address is found")
