# !/usr/bin/env python
# coding: utf-8
# got some idea for this implementations? read here: https://medium.com/coinmonks/upgradeable-proxy-contract-from-scratch-3e5f7ad0b741
from datetime import datetime

from eth_utils import to_checksum_address
from web3.contract import Contract

from moody.libeb import MiliDoS
from moody import Config
from moody.m.proxy_admin import ProxyAdmin


def getInfo(manifest: MiliDoS, address: str, abi: str) -> Contract:
    return manifest.w3.eth.contract(address=address, abi=abi)


def getData(manifest: MiliDoS, address: str, abi: str, method: str, params: any) -> bytes:
    hex = getInfo(manifest, to_checksum_address(address), abi).encodeABI(fn_name=method, args=params)
    return hex


def manifest(network: Config, root_path: str, k: str, override: list = []) -> MiliDoS:
    """
    To show up the manifest for further developments
    :param network:
    :param root_path:
    :param k:
    :param override:
    :return:
    """
    deploy2 = MiliDoS(network).withPOA()
    deploy2.setWorkspace(root_path).Auth(k)
    if len(override) > 0:
        deploy2.OverrideGasConfig(override[0], override[1])
    else:
        deploy2.OverrideGasConfig(6000000, 2000000000)
    return deploy2


def implementingProxyAdmin(package_manifest: MiliDoS) -> ProxyAdmin:
    """
    automatically deploy the proxy admin contracts
    :param package_manifest:
    :return:
    """
    if not package_manifest.hasContractName("ProxyAdmin"):
        rs = package_manifest.deployImple("ProxyAdmin")

        if not rs:
            print("⛔️ failure in deploying ProxyAdmin")
            exit(5)

        proxyadmin_address = package_manifest.deployed_address
    else:
        proxyadmin_address = package_manifest.getAddr("ProxyAdmin")
        print(
            f"⛔️ cannot deploy ProxyAdmin since another one is existed. Please take care of that. {proxyadmin_address}")

    admin = ProxyAdmin(package_manifest, proxyadmin_address)
    admin.CallAutoConf(package_manifest).CallDebug(True)

    return admin


def deployProxyUniversial(
        root_path: str,
        network: Config,
        deployer_key: str,
        class_name: str,
        admin_signer: str,
        args: list = None,
        args_initialization: list = None
):
    """
    followed the convention from https://docs.openzeppelin.com/upgrades-plugins/1.x/truffle-upgrades
    This will automatically check that the Box contract is upgrade-safe, set up a proxy admin (if needed),
    deploy an implementation contract for the Box contract (unless there is one already from a previous
    deployment), create a proxy, and initialize it by calling initialize(42).

    Then, in a future migration, you can use the upgradeProxy function to upgrade the deployed instance to a
    new version. The new version can be a different contract (such as BoxV2), or you can just modify the
    existing Box contract and recompile it - the plugin will note it changed.

    :param root_path:
    :param network:
    :param deployer_key:
    :param class_name:
    :param admin_signer:
    :param args: for the implementation contract
    :param args_initialization: for initialization
    :return:
    """
    package_manifest = manifest(network, root_path, deployer_key)
    deployProxy(package_manifest, class_name, admin_signer, args, args_initialization)


def checkForUpgradableContract(manifest: MiliDoS, class_name_contract: str) -> bool:
    """
    the detail in works for checking the upgradable standard contract
    :param manifest:
    :param class_name_contract:
    :return:
    """
    manifest.provide_artifact_extends(class_name_contract)
    contract_abi = manifest.artifact_manager.abi
    for h in contract_abi:
        if "name" in h and h["name"] == "initialize":
            return True
    return False


def check_initialize(manifest: MiliDoS, name: str):
    """
    the manifest is not milidos
    :param manifest:
    :param name:
    :return:
    """
    if not checkForUpgradableContract(manifest, name):
        print(f"⛔️ Sorry, {name} is not an initializable contract. Please double check it.")
        exit(106)


def check_proxy_standard(package_manifest: MiliDoS, class_name_contract: str):
    """
    check if the proxy address has all the previous information
    :param manifest:
    :param class_name_contract:
    :return:
    """
    package_manifest.setTargetClass(class_name_contract)
    bool_a = package_manifest.hasField("proxy_admin")
    bool_b = package_manifest.hasField("implementation")
    if not bool_a or not bool_b:
        print(
            f"⛔️ Sorry, the {class_name_contract} does not have enough information to tell that is a upgradable contract.")
        exit(103)


def deployCustomProxy(
        package_manifest: MiliDoS,
        proxy_name: str,
        class_name: str,
        admin_signer: str,
        argsbytes: list = None,
        args_initialization: list = None):
    """
    This used to serve the customized proxy that built by the third party or the non-standar proxy contracts defined by the users.
    :param package_manifest:
    :param class_name:
    :param admin_signer:
    :param argsbytes: for the implementation contract
    :param args_initialization: for the implementation contract
    :return:
    """
    check_initialize(package_manifest, class_name)
    admin = implementingProxyAdmin(package_manifest)

    if not package_manifest.hasContractName(class_name):
        rs = package_manifest.deploy(class_name, argsbytes)

        if not rs:
            print("⛔️ failure in implementation deployment")
            exit(5)

        logic_address = package_manifest.deployed_address
    else:
        logic_address = package_manifest.getAddr(class_name)

    if not package_manifest.deployed_address:
        print("⛔️ address is not deployed yet")
        return

    delegatecall_data = getData(
        manifest=package_manifest,
        address=logic_address,
        abi=package_manifest.artifact_manager.abi,
        method="initialize",
        params=args_initialization)

    print(f"call_data for initialization: {delegatecall_data}")

    if not package_manifest.hasContractName(proxy_name):
        # todo: not every custom contracts will follow this.
        rs = package_manifest.deploy(proxy_name, [
            logic_address,
            admin.contract_address,
            delegatecall_data
        ])

        if not rs:
            print("⛔️ There is an error from deploying the upgradable-proxy contract")
            print("⛔️ failure in deploying custom proxy..")
            exit(5)

        proxy_address = package_manifest.deployed_address
    else:
        proxy_address = package_manifest.getAddr(proxy_name)

    if not package_manifest.deployed_address:
        print("⛔️ address is not deployed yet")
        return

    print(f"Finally the proxy address is established: {proxy_address}")

    administrator = admin.get_proxy_admin(proxy_address)
    if administrator != "":
        print(f"Already got the admin from {administrator} and the signer is {admin_signer}")
    else:
        print(f"Set new signer to {admin_signer}")
        admin.change_proxy_admin(proxy_address, admin_signer)
    print("🈶 All done ===")


def deployCustomProxyForImplementedAddress(
        package_manifest: MiliDoS,
        proxy_name: str,
        imple_address: str,
        admin_signer: str,
        args_initialization: list = None
):
    admin = implementingProxyAdmin(package_manifest)

    delegatecall_data = getData(
        manifest=package_manifest,
        address=imple_address,
        abi=package_manifest.artifact_manager.abi,
        method="initialize",
        params=args_initialization)

    print(f"call_data for initialization: {delegatecall_data}")

    if not package_manifest.hasContractName(proxy_name):
        # todo: not every custom contracts will follow this.
        rs = package_manifest.deploy(proxy_name, [
            imple_address,
            admin.contract_address,
            args_initialization
        ])

        if not rs:
            print("⛔️ There is an error from deploying the upgradable-proxy contract")
            print("⛔️ failure in deploying custom proxy..")
            exit(5)

        proxy_address = package_manifest.deployed_address
    else:
        proxy_address = package_manifest.getAddr(proxy_name)

    if not package_manifest.deployed_address:
        print("⛔️ address is not deployed yet")
        return

    print(f"Finally the proxy address is established: {proxy_address}")

    administrator = admin.get_proxy_admin(proxy_address)
    if administrator != "":
        print(f"Already got the admin from {administrator} and the signer is {admin_signer}")
    else:
        print(f"Set new signer to {admin_signer}")
        admin.change_proxy_admin(proxy_address, admin_signer)
    print("🈶 All done ===")


def deployProxyForImplementedAddress(
        package_manifest: MiliDoS,
        implementation_class_name: str,
        admin_signer: str,
):
    """
    For the more complicated projects where the implementation contract needs to be customized deployed first
    and then come back for this proxy wrapper. And this is more desirable to use.

    1. please deploy the implementation contract first the (logical contract)
    2. using this function call will wrap the TransparentUpgradeableProxy into the logical contract

    :param package_manifest:
    :param imple_address:
    :param admin_signer:
    :param args_initialization_: Ethereum transactions contain a field called data. This field is optional and must be empty when sending ethers, but, when interacting with a contract, it must contain something. It contains call data, which is information required to call a specific contract function.
    :return:
    """
    proxyClassName = "TransparentUpgradeableProxy"
    admin = implementingProxyAdmin(package_manifest)
    imple_address = package_manifest.getAddr(implementation_class_name)
    print(f"proxy admin address is {admin.contract_address}")
    print(f"proxy implementation address is {imple_address}")

    if not package_manifest.hasContractName(proxyClassName):
        rs = package_manifest.deployImple(proxyClassName, [
            imple_address,
            admin.contract_address,
            ""
        ])
        if not rs:
            print(f"⛔️ failure in deploying {proxyClassName}")
            exit(5)
        proxy_address = package_manifest.deployed_address

        # proxy_address = package_manifest.getAddr(proxyClassName)

        package_manifest.replaceAddr(implementation_class_name, proxy_address)
        package_manifest.setTargetClass(implementation_class_name)
        package_manifest.setKV("proxy_admin", admin.contract_address)
        package_manifest.setKV("implementation", imple_address)
        package_manifest.setKV("version", 1)

        package_manifest.removeTarget("ProxyAdmin")
        package_manifest.removeTarget("TransparentUpgradeableProxy")

        package_manifest.complete_deployment()

    else:
        proxy_address = package_manifest.getAddr("TransparentUpgradeableProxy")
        print(f"⛔️ cannot deploy proxy since another one is existed. Please take care of that. {proxy_address}")
        exit(17)

    administrator = admin.get_proxy_admin(proxy_address)

    if administrator != "":
        print(f"Already got the admin from {administrator} and the signer is {admin_signer}")

    else:
        print(f"Set new signer to {admin_signer}")
        admin.change_proxy_admin(proxy_address, admin_signer)

    print("🈶 All done ===")


def deployProxy(
        package_manifest: MiliDoS,
        class_name: str,
        admin_signer: str,
        args_: list = None,
        args_initialization_: list = None
):
    """
    followed the convention from https://docs.openzeppelin.com/upgrades-plugins/1.x/truffle-upgrades
    This will automatically check that the Box contract is upgrade-safe, set up a proxy admin (if needed),
    deploy an implementation contract for the Box contract (unless there is one already from a previous
    deployment), create a proxy, and initialize it by calling initialize(42).

    Then, in a future migration, you can use the upgradeProxy function to upgrade the deployed instance to a
    new version. The new version can be a different contract (such as BoxV2), or you can just modify the
    existing Box contract and recompile it - the plugin will note it changed.

    :param package_manifest:
    :param class_name:
    :param admin_signer:
    :param args_: for the implementation contract
    :param args_initialization_: for the implementation contract
    :return:
    """

    check_initialize(package_manifest, class_name)
    admin = implementingProxyAdmin(package_manifest)

    if not package_manifest.hasContractName(class_name):
        rs = package_manifest.deploy(class_name, args_)

        if not rs:
            print("⛔️ failure in deployment..")
            exit(5)

        logic_address = package_manifest.deployed_address
    else:
        logic_address = package_manifest.getAddr(class_name)

    if not package_manifest.deployed_address:
        print("⛔️ address is not deployed yet")
        return

    if args_initialization_ is not None:
        delegatecall_data = getData(
            manifest=package_manifest,
            address=logic_address,
            abi=package_manifest.artifact_manager.abi,
            method="initialize",
            params=args_initialization_)

        print(f"call_data for initialization: {delegatecall_data}")
    else:
        args_initialization_ = ""

    if not package_manifest.hasContractName("TransparentUpgradeableProxy"):
        rs = package_manifest.deployImple("TransparentUpgradeableProxy", [
            logic_address,
            admin.contract_address,
            args_initialization_
        ])
        if not rs:
            print("⛔️ failure in deploying TransparentUpgradeableProxy")
            exit(5)

        proxy_address = package_manifest.deployed_address
    else:
        proxy_address = package_manifest.getAddr("TransparentUpgradeableProxy")

    administrator = admin.get_proxy_admin(proxy_address)

    if administrator != "":
        print(f"Already got the admin from {administrator} and the signer is {admin_signer}")

    else:
        print(f"Set new signer to {admin_signer}")
        admin.change_proxy_admin(proxy_address, admin_signer)

    print("🈶 All done ===")


def upgradeTo(package_manifest: MiliDoS, newVerClassName: str, fromClassName: str, args: any = None):
    """
    to make the upgrade
    1. deploy the new implementation contract
    2. check the old proxy contract
    3. perform an upgrade
    :param package_manifest:
    :param newVerClassName:
    :param fromClassName:
    :param args:
    :return:
    """
    if not package_manifest.hasContractName(newVerClassName):
        print(f"⛔️ Sorry, the {newVerClassName} is not found.")
        exit(101)

    if not package_manifest.hasContractName(fromClassName):
        print(f"⛔️ Sorry, the {fromClassName} is not found. Are you sure that you have deployed this contract?")
        exit(102)

    check_proxy_standard(package_manifest, fromClassName)
    check_initialize(package_manifest, newVerClassName)

    proxy_address = package_manifest.getAddr(fromClassName)
    new_imple_address = package_manifest.getAddr(newVerClassName)
    proxy_admin_address = package_manifest.getString("proxy_admin")
    proxy_imple_address = package_manifest.getString("implementation")
    admin = ProxyAdmin(package_manifest, proxy_admin_address)
    admin.CallAutoConf(package_manifest).CallDebug(True)
    current_ver_implementation = admin.get_proxy_implementation(proxy_address)
    print(f"Found current implementation address {current_ver_implementation}")
    print(f"Found current implementation address from record {proxy_imple_address}, and it should match.")
    print(
        f"🈶 Now the new implementation is {new_imple_address} and now it will perform an upgrade to this. Please make sure all the parameters or arguements are correct")

    def success(tx: str, name: str):
        package_manifest.setKV("implementation", new_imple_address)
        package_manifest.setKV("version", package_manifest.getVal("version") + 1)
        print(f"🈶 All done :: {tx}")

    def f(name: str, message: str):
        print("⛔️ failure in deploying implementation")

    admin.EnforceTxReceipt(True)
    admin.onSuccssCallback(success)
    admin.onFailCallback(f)
    if args is None:
        admin.upgrade(proxy_address, new_imple_address)
    else:
        admin.upgrade_and_call(proxy_address, new_imple_address, args)
