from ..m.tc20 import Tc20


class TimeLockerMs:
    def __init__(self):
        self.lock = False
        self.cc = False

    def locks(self):
        self.lock = True

    def appendAction(self, address_contract: str, method):
        # contract = Tc20(address_contract).CallDebug(False).CallContractFee(10000000)
        # contract.add_minter("sokcpokspdockpokd")
        ## get_function_by_signature
        # signature =
        # data =
        # value
        pass
