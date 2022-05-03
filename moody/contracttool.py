#!/usr/bin/env python
# coding: utf-8
from typing import Tuple

from eth_account import Account

from . import Config, Bolors
from .libeb import MiliDoS


class ContractTool(MiliDoS):
    """
    This is the helper tool to help generating the easy access to the contract information
    """
    classes = [
        "Genesis", "GenesisKey"
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

    def AuthIndex(self, w_index: int) -> "ContractTool":
        (a, c) = self.auth(w_index)
        localAc = Account.from_key(c)
        self.w3.eth.account = localAc
        is_address = self.w3.isAddress(localAc.address)
        self.accountAddr = localAc.address
        print(f"You are now using {localAc.address} and it is a {'valid key' if is_address else 'invalid key'}")
        return self

    def ClassList(self, setup_list: list) -> "ContractTool":
        self.classes = setup_list
        return self

    def check_fill(self, inset: dict, cls_name: str) -> None:
        if len(inset) > 0:
            if cls_name not in self._contract_dict:
                print(f"🍽  Check class: {Bolors.WARNING}{cls_name}{Bolors.RESET}->{inset[cls_name]}")
                self._contract_dict[cls_name] = inset[cls_name]

    def FillAddresses(self, deploy_list_input: dict) -> "ContractTool":
        if len(self.deploy_list) == 0 or len(deploy_list_input) == 0:
            print(f"{Bolors.FAIL}deploy list not found {Bolors.RESET}")
            exit(0)
            return self

        listuage = dict()

        if len(self.deploy_list) == 0:
            listuage = deploy_list_input

        elif len(deploy_list_input) == 0:
            listuage = self.deploy_list
        else:
            listuage = deploy_list_input

        if len(listuage) == 0:
            print(f"{Bolors.FAIL}deploy list still not found {Bolors.RESET}")
            exit(0)
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

    """
    This is the batch function to transfer native coins
    """

    def DistributeCoins(self, from_account_index: int, loops: int, exclude: list, gas: int, price: int) -> None:
        ind = 0
        # self.AuthIndex(from_account_index)
        while ind < loops:
            if ind in exclude:
                ind += 1
                continue
            if from_account_index == ind:
                ind += 1
                continue
            self.TransferRefer(ind, 0.1, gas, price)
            ind += 1

    """
    The function used for transfer the native coin
    """

    def Transfer(self, address_receive: str, amount: float, gas_limit: int = 0, gas_price: int = 0) -> str:
        tx = {
            'to': address_receive,
            'chainId': self.w3.eth.chainId,
            'gas': self.gas if gas_limit == 0 else gas_limit,
            'gasPrice': self.gasPrice if gas_price == 0 else gas_price,
            'nonce': self.w3.eth.getTransactionCount(self.w3.eth.account.address),
            'value': self.w3.toWei(amount, "ether")
        }
        # (a, p) = self.auth(w_index)
        # print(f"private key get {p}")
        signed_txn = self.w3.eth.account.sign_transaction(tx)
        print(f"🚸 Before transaction sending data\n{tx}")
        tx_hash = self.w3.eth.sendRawTransaction(signed_txn.rawTransaction)
        hash_tx_str = self.w3.toHex(tx_hash)
        print(f"☕️ Waiting for the block confirmation now ...")
        self.w3.eth.waitForTransactionReceipt(tx_hash)
        print(f"✅ {Bolors.OK}{hash_tx_str}{Bolors.RESET}")
        return hash_tx_str

    def TransferRefer(self, w_index: int, amount: float, gas_limit: int = 0, gas_price: int = 0) -> str:
        return self.Transfer(self.referrer(w_index), amount, gas_limit, gas_price)


def implementContract(manifest: MiliDoS, class_name: str, args: list = []) -> str:
    if manifest.hasContractName(class_name) is False:
        manifest.deploy(class_name, args)
        return manifest.deployed_address
    else:
        return manifest.getAddr(class_name)
