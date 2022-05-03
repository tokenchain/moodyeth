# !/usr/bin/env python
# coding: utf-8
# from web3.auto import w3
from datetime import datetime
from moody.libeb import MiliDoS
from moody import Config
from moody.m.proxy_admin import ProxyAdmin


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

    admin = ProxyAdmin(package_manifest, proxyadmin_address)
    admin.CallAutoConf(package_manifest).CallDebug(True)

    return admin


def deployProxyUniversial(
        root_path: str,
        network: Config,
        deployer_key: str,
        class_name: str,
        admin_signer: str,
        args: list,
        args_initialization: list
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
        if "name" in h and h["name"] is "initialize":
            return True
    return False


def checkBreak(manifest: MiliDoS, name: str):
    """
    the manifest is not milidos
    :param manifest:
    :param name:
    :return:
    """
    if not checkForUpgradableContract(manifest, name):
        print(f"⛔️ Sorry, {name} is not an upgradable contract. Please double check it.")


def deployCustomProxy(
        package_manifest: MiliDoS,
        proxy_name: str,
        class_name: str,
        admin_signer: str,
        argsbytes: list,
        args_initialization: list):
    """
    This used to serve the customized proxy that built by the third party or the non-standar proxy contracts defined by the users.
    :param package_manifest:
    :param class_name:
    :param admin_signer:
    :param argsbytes: for the implementation contract
    :param args_initialization: for the implementation contract
    :return:
    """
    checkBreak(package_manifest, class_name)
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

    if not package_manifest.hasContractName(proxy_name):
        # todo: not every custom contracts will follow this.
        rs = package_manifest.deploy(proxy_name, [
            logic_address,
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


def deployProxy(
        package_manifest: MiliDoS,
        class_name: str,
        admin_signer: str,
        args_: list,
        args_initialization_: list
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

    checkBreak(package_manifest, class_name)
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


def upgradeTo(package_manifest: MiliDoS, newVerClassName: str, args: any = None):
    if not package_manifest.hasContractName("ProxyAdmin"):
        print("⛔️ Sorry, the proxy admin is not found. Please initialize deployProxy or having the proxyadmin in the json file.")
        exit(6)

    if not package_manifest.hasContractName("TransparentUpgradeableProxy"):
        print("⛔️ Sorry, the proxy contract is not found. Please initialize deployProxy or having the proxyadmin in the json file.")
        exit(7)
    checkBreak(package_manifest, newVerClassName)
    proxy_address = package_manifest.getAddr("TransparentUpgradeableProxy")
    proxyadmin_address = package_manifest.getAddr("ProxyAdmin")
    admin = ProxyAdmin(package_manifest, proxyadmin_address)
    admin.CallAutoConf(package_manifest).CallDebug(True)
    current_ver_implementation = admin.get_proxy_implementation(proxy_address)
    print(f"Found current implementation address {current_ver_implementation}")
    # todo: check if this contract is the upgradable standard
    print(f"Deploy new implementation for {newVerClassName}")
    rs = package_manifest.deploy(newVerClassName)
    if not rs:
        print("⛔️ failure in deploying implementation")
        exit(5)

    new_imple_address = package_manifest.deployed_address
    print(f"🈶 Now the new implementation is {new_imple_address} and now it will perform an upgrade to this. Please make sure all the parameters or arguements are correct")
    if args is None:
        admin.upgrade(proxy_address, new_imple_address)
    else:
        admin.upgrade_and_call(proxy_address, new_imple_address, args)

    print("🈶 All done ===")
