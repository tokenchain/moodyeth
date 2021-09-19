from ..libeb import MiliDoS


class ProxyUpgrade:
    """
    Preforming an upgrade contract to the previous contract
    """

    def __init__(self, _from: MiliDoS):
        self.engine = _from

    @property
    def AdminProxy(self) -> str:
        if self.engine.hasContractName("AdminProxy"):
            return self.engine.getAddr("AdminProxy")
        else:
            raise ValueError("not AdminProxy contract address is found")

    @property
    def UpgradeAbility(self) -> str:
        if self.engine.hasContractName("UpgradingProxy"):
            return self.engine.getAddr("UpgradingProxy")
        else:
            raise ValueError("not UpgradingProxy contract address is found")

    def adminProxySetup(self):
        pass

    def upgrade(self, upgradeProxyContractName: str, original_tracking_logic_contract: str, admin: str, calldata: bytes):
        upgrading_contract = ""
        if self.engine.hasContractName(upgradeProxyContractName):
            upgrading_contract = self.engine.getAddr(upgradeProxyContractName)
        else:
            result = self.engine.deploy(upgradeProxyContractName, [original_tracking_logic_contract, admin, calldata])
            if result is False:
                print("⛔️ There is an error from deploying the upgrade proxy contract")
                exit(0)

            if self.engine.hasContractName(upgradeProxyContractName) is False:
                print("⛔️ The proxy contract is deployed but it is not found from the deployment results. Check: deploy_results.json for details.")
                exit(0)

            upgrading_contract = self.engine.getAddr(upgradeProxyContractName)

        print(f"🈶 The final proxy deployment contract is found and shown as {upgrading_contract}")
