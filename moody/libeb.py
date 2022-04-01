import codecs
import json
import os
import subprocess
import time
from threading import Lock
from typing import List, Tuple, Optional

# ========================== Of course
from hexbytes import HexBytes
from web3 import Web3, HTTPProvider
from web3.contract import Contract as Web3Contract
from web3.datastructures import AttributeDict
from web3.exceptions import TransactionNotFound, ContractLogicError, InvalidAddress, TimeExhausted
from web3.logs import DISCARD
from web3.middleware import geth_poa_middleware
from web3.types import BlockData

# ========================== Of course
from . import Bolors, Evm
from .buildercompile.remotecompile import BuildRemoteLinuxCommand
from .buildercompile.transpile import BuildLang
from .conf import Config
from .exceptions import FoundUndeployedLibraries
from .paths import Paths


def web3_provider(address: str) -> Web3:
    try:
        if address.startswith('http'):  # HTTP
            return Web3(Web3.HTTPProvider(address))
        if address.startswith('ws'):  # WebSocket
            return Web3(Web3.WebsocketProvider(address))
        return Web3(Web3.IPCProvider(address))
    except FileNotFoundError:
        raise ValueError("Failed to initialize web3 provider (is eth_node set?)") from None


w3_lock = Lock()
event_lock = Lock()
statement = 'End : {}, IO File {}'


def extract_tx_by_address(address, block: BlockData) -> list:
    # Note: block attribute dict has to be generated with full_transactions=True flag
    return [tx for tx in block.transactions if tx.to and address.lower() == tx.to.lower()]


def event_log(tx_hash: str, events: List[str], provider: Web3, contract: Web3Contract) -> Tuple[str, Optional[AttributeDict]]:
    """
    Extracts logs of @event from tx_hash if present
    :param tx_hash:
    :param events: Case sensitive events name
    :param provider:
    :param contract: Web3 Contract
    :return: event name and log represented in 'AttributeDict' or 'None' if not found
    """
    try:
        receipt = provider.eth.getTransactionReceipt(tx_hash)
    except TransactionNotFound:
        time.sleep(3000)  # hard coded sleep for 3 seconds... maybe this will help?
        # retry
        try:
            receipt = provider.eth.getTransactionReceipt(tx_hash)
        except TransactionNotFound:
            return '', None

    for event in events:
        # we discard warning as we do best effort to find wanted event, not always there
        # as we listen to the entire contract tx, might
        log = getattr(contract.events, event)().processReceipt(receipt, DISCARD)
        if log:
            data_index = 0
            return event, log[data_index]
    # todo: fix this - seems like some weird return
    return '', None


def normalize_address(address: str):
    """Converts address to address acceptable by web3"""
    return Web3.toChecksumAddress(address.lower())


def Logd(anystr: any):
    print(anystr)


def writeFile(content, filename):
    fo = open(filename, "w")
    fo.write(content)
    fo.close()
    print(statement.format(time.ctime(), filename))


class HexJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)


def _parseValue(val):
    # check for nested dict structures to iterate through
    if 'dict' in str(type(val)).lower():
        return toDict(val)
    # convert 'HexBytes' type to 'str'
    elif 'HexBytes' in str(type(val)):
        return val.hex()
    else:
        return val


def toDict(dictToParse):
    # convert any 'AttributeDict' type found to 'dict'
    parsedDict = dict(dictToParse)
    for key, val in parsedDict.items():
        if 'list' in str(type(val)):
            parsedDict[key] = [_parseValue(x) for x in val]
        else:
            parsedDict[key] = _parseValue(val)
    return parsedDict


import re

regex1 = r"\/\/*.*"


class IDos:
    def hasContractName(self, name: str) -> bool:
        pass

    def getAddr(self, keyname: str) -> str:
        pass

    def isAddress(self, add: str) -> bool:
        pass


class BinOp:
    def __init__(self, bin_content: str, file_name: str):
        self.bin_raw = bin_content
        self.bin_knifed = bin_content
        self.bin_undeploy_lib = dict()
        self.file_name = file_name
        self.debug = False

    def setDebug(self, de: bool):
        self.debug = de

    def GetRawBin(self) -> str:
        return self.bin_raw

    def GetKnifedBin(self) -> str:
        return self.bin_knifed

    def checkBinForUndeployLib(self) -> bool:
        matches = re.finditer(regex1, self.bin_raw, re.MULTILINE)
        found = False
        for matchNum, match in enumerate(matches, start=1):
            print("Library {matchNum} is found at {start}-{end}: {match}".format(matchNum=matchNum, start=match.start(), end=match.end(), match=match.group()))
            k, v = self.fromLine(match.group())
            self.bin_undeploy_lib[k] = v
            found = True
        return found

    def fromLine(self, input_line: str) -> Tuple[str, str]:
        class_name = input_line.split(":")[1]
        return class_name, input_line

    def _placehd(self, instruction_line: str) -> str:
        return "__{}__".format(str(instruction_line).split("->")[0].strip(" //"))

    def anaylze(self, databank: IDos) -> bool:
        if len(self.bin_undeploy_lib) == 0:
            print("🚧 Nothing to process")
            return False

        for class_name, instruction_line in self.bin_undeploy_lib.items():
            if databank.hasContractName(class_name) is True:
                print(f"💽 Found support Class {class_name} - deployment address")
                if databank.isAddress(databank.getAddr(class_name)):
                    self._knifeBinClass(class_name, self._placehd(instruction_line), databank.getAddr(class_name))
                else:
                    print("🧊 The found library address is not valid - {}, {}".format(class_name, databank.getAddr(class_name)))
                    raise FoundUndeployedLibraries
            else:
                print("⚠️ Unfound library Error- {}, please make sure you have this library deployed.".format(class_name))
                raise FoundUndeployedLibraries

        self.bin_knifed = self.bin_knifed.splitlines(True)[0]
        self.bin_knifed = self.bin_knifed.replace("\n", "")
        # self.bin_knifed = "0x" + self.bin_knifed
        if self.debug is True:
            print(f"After processed bin file - {self.file_name}.bin (should be done now)")
            print(self.bin_knifed)
            # print(self.bin_raw)
            print("File content end ##")
        else:
            print(f"After processed bin file - {self.file_name}.bin")

        return True

    def _knifeBinClass(self, c: str, k: str, address: str) -> None:
        # address_step_1 = address.lower()
        address_step_2 = address.replace("0x", "")
        self.bin_knifed = self.bin_knifed.replace(k, address_step_2)
        print(f"🍡 Linked successfully for Solidity Class {c} with {address}")


class SolWeb3Tool(object):
    OUTPUT_BUILD = "build"
    WORKSPACE_PATH = ""
    solfolder = ""
    file_name = "xxx.sol"
    prefixname = ""
    statement = 'End : {}, IO File {}'

    def __init__(self):
        self._abi = None
        self._bin = None
        self.combined_data = None
        self._key = None

    def setBuildNameSpace(self, path: str) -> "SolWeb3Tool":
        self.OUTPUT_BUILD = path
        return self

    def setBasePath(self, path: str) -> "SolWeb3Tool":
        self.WORKSPACE_PATH = path
        return self

    def GetCodeClassFromBuild(self, class_name: str) -> "SolWeb3Tool":
        """
        get the independent files and content from the file system
        :param class_name:
        :return:
        """
        p1bin = os.path.join(self.WORKSPACE_PATH, self.OUTPUT_BUILD, "{}.bin".format(class_name))
        p2abi = os.path.join(self.WORKSPACE_PATH, self.OUTPUT_BUILD, "{}.abi".format(class_name))
        self._bin = codecs.open(p1bin, 'r', 'utf-8-sig').read()
        self._abi = json.load(codecs.open(p2abi, 'r', 'utf-8-sig'))
        return self

    def GetCombinedFile(self):
        pathc = os.path.join(self.WORKSPACE_PATH, self.OUTPUT_BUILD, "combined.json")
        try:
            pathcli = codecs.open(pathc, 'r', 'utf-8-sig')
            self.combined_data = json.load(pathcli)
        except Exception as e:
            print("Problems from loading items from the file: ", e)
        return self

    def byClassName(self, path: str, classname: str) -> str:
        return "{prefix}:{name}".format(prefix=path, name=classname)

    def GetCodeTag(self, fullname):
        return self.combined_data["contracts"][fullname]["abi"], self.combined_data["contracts"][fullname]["bin"]

    def GetCode(self, path: str, classname: str) -> [str, str]:
        """
        get the code and abi from combined.json
        :param path:
        :param classname:
        :return:
        """
        abi = self.combined_data["contracts"][self.byClassName(path, classname)]["abi"]
        bin = self.combined_data["contracts"][self.byClassName(path, classname)]["bin"]
        return abi, bin

    def CompileBash(self) -> None:
        """
        This is the remote command to execute the solc_remote bash file
        using remote compile method to compile the sol files
        all works will be done with the remote server or using the docker
        """
        list_files = subprocess.run(["{}/solc_remote".format(self.WORKSPACE_PATH)])
        print("The exit code was: %d" % list_files.returncode)

    @property
    def abi(self) -> str:
        return self._abi

    @property
    def bin(self) -> str:
        return self._bin

    @property
    def workspace(self):
        return self.WORKSPACE_PATH

    def StoreTxResult(self, tx_result_data: any, filepath: str):
        predump = toDict(tx_result_data)
        writeFile(json.dumps(predump, ensure_ascii=False), filepath)


class MiliDoS(IDos):
    """
    wrap the web3 into the package
    @
    """

    EVM_VERSION = Evm.BERLIN

    def __init__(self, _nodeCfg: Config):
        # the hidden list
        self._contract_dict = dict()
        self._sol_list = list()
        # publicly accessible
        self.base_path = ""
        self.accountAddr = None
        self.pathfinder = None
        self.artifact_manager = None
        self._sol_link = None
        self.is_deploy = False
        self.last_class = ""
        self.list_type = "list_address"
        self.network_cfg = _nodeCfg
        self.w3 = web3_provider(_nodeCfg.rpc_url)
        self._optimizations = 200
        result = self.w3.isConnected()
        if not result:
            print(f"try to connect {self.network_cfg.network_name}  {Bolors.WARNING} {self.network_cfg.rpc_url}: {result} {Bolors.RESET}")
            exit(0)
            return
        else:
            print(f"You are now connected to {Bolors.OK} {self.network_cfg.network_name} {self.network_cfg.rpc_url} {Bolors.RESET}")

    def withPOA(self) -> "MiliDoS":
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        return self

    def isAddress(self, address: str) -> bool:
        return self.w3.isAddress(address)

    def connect(self, workspace: str, history: any) -> None:

        """
        connect the existing deployed contract
        :param workspace: the workspace directory
        :param history: the deployed history folder under the deploy_history
        :return:
        """
        self.is_deploy = False
        self.artifact_manager = SolWeb3Tool()
        if history is False:
            self.pathfinder = Paths(workspace).setDefaultPath().Network(self.network_cfg.network_name)
        else:
            self.pathfinder = Paths(workspace).SetUseHistory(history).Network(self.network_cfg.network_name)

        self.ready_io(True)

    def SetupContract(self):
        pass

    def after_deployment_initialize_settings(self):
        """
        setup contract starting params
        setup the starting time using bang
        setup the first member
        :return:
        """
        pass

    def setWorkspace(self, path: str, readio: bool = True) -> "MiliDoS":
        self.base_path = path
        self.pathfinder = Paths(path).setDefaultPath().Network(self.network_cfg.network_name)
        if readio:
            self.ready_io(True)
        return self

    def setClassSolNames(self, to_compile_contract_list: list) -> "MiliDoS":
        self._sol_list = to_compile_contract_list
        return self

    def setClassSolLinks(self, compile_links: list) -> "MiliDoS":
        self._sol_link = compile_links
        return self

    def setEvm(self, verc: str) -> "MiliDoS":
        self.EVM_VERSION = verc
        return self

    def setOptimizationRuns(self, b: int) -> "MiliDoS":
        self._optimizations = b
        return self

    def remoteCompile(self, ver: str) -> "MiliDoS":
        if ver == "":
            print("there is no solidity version specified")
            exit(0)
        self.pathfinder.setSolVersion(ver)
        self.pathfinder.setEvm(self.EVM_VERSION)
        BuildRemoteLinuxCommand(self.pathfinder, self._optimizations, self._sol_list, self._sol_link)
        return self

    def localTranspile(self, dapp_folder: str = "app") -> "MiliDoS":
        self.pathfinder.updateTargetDappFolder(dapp_folder)
        BuildLang(self.pathfinder, self._sol_list)
        return self

    def get_block(self, block_identifier, full_transactions: bool = False):
        """
        to see the block information
        :param block_identifier:
        :param full_transactions:
        :return:
        """
        with w3_lock:
            res = self.w3.eth.getBlock(block_identifier, full_transactions)
        return res

    def erc20_contract(self):
        cTool = SolWeb3Tool()
        cTool.setBuildNameSpace("artifact").GetCodeClassFromBuild("ERC20")
        return self.w3.eth.contract(abi=cTool.abi)

    def estimate_gas_price(self):
        return self.w3.eth.gasPrice

    def send_contract_tx(self, contract: Web3Contract, function_name: str, from_acc: str,
                         private_key: bytes, gas: int = 0, gas_price: int = 0, _value: int = 0,
                         args: Tuple = ()):
        """
        Creates the contract tx and signs it with private_key to be transmitted as raw tx
        """

        tx = getattr(contract.functions, function_name)(*args).buildTransaction(
            {
                'from': from_acc,
                'chainId': self.w3.eth.chainId,
                # gas_price is in gwei
                'gasPrice': gas_price * 1e9 if gas_price else self.estimate_gas_price(),
                'gas': gas or None,
                'nonce': self.w3.eth.getTransactionCount(from_acc, block_identifier='pending'),
                'value': _value
            })
        signed_txn = self.w3.eth.account.sign_transaction(tx, private_key)
        return self.w3.eth.sendRawTransaction(signed_txn.rawTransaction)

    def contract_event_in_range(self, contract, event_name: str, from_block: int = 0, to_block: Optional[int] = None) -> None:
        """
        scans the blockchain, and yields blocks that has contract tx with the provided event
        Note: Be cautions with the range provided, as the logic creates query for each block which could be a bottleneck.
        :param from_block: starting block, defaults to 0
        :param to_block: end block, defaults to 'latest'
        :param provider:
        :param logger:
        :param contract:
        :param event_name: name of the contract emit event you wish to be notified of
        """
        if to_block is None:
            to_block = self.w3.eth.blockNumber

        with w3_lock:

            if isinstance(self.w3.provider, HTTPProvider):
                for block_num in range(from_block, to_block + 1):
                    block = self.w3.eth.getBlock(block_num, full_transactions=True)
                    contract_transactions = extract_tx_by_address(contract.address, block)

                    if not contract_transactions:
                        continue
                    for tx in contract_transactions:
                        _, log = event_log(tx_hash=tx.hash, events=[event_name], provider=self.w3, contract=contract.tracked_contract)
                        if log is None:
                            continue
                        yield log
            else:
                event = getattr(contract.tracked_contract.events, event_name)
                event_filter = event.createFilter(fromBlock=from_block, toBlock=to_block)

                for tx in event_filter.get_new_entries():
                    _, log = event_log(tx_hash=tx.hash, events=[event_name], provider=self.w3, contract=contract.tracked_contract)

                    if log is None:
                        continue

                    yield log

    def Auth(self, private_key_line: str) -> "MiliDoS":
        # f"0x{private_key_line}"
        keyLo = self.w3.eth.account.from_key(f"0x{private_key_line}")
        # self.w3.eth.defaultAccount = keyoo.address
        self.w3.eth.account = keyLo
        # self.w3.eth.get_transaction_count
        # self.w3.eth.accounts[0] = keyLo.address
        # self.w3.eth.defaultAccount(f"0x{keyLo.key}")
        is_address = self.w3.isAddress(keyLo.address)
        # self.w3.isChecksumAddress(keyLo.address)
        self.accountAddr = keyLo.address
        print(f"🔫 You are now using {keyLo.address} and it is a {'valid key' if is_address else 'invalid key'}")

        return self

    def estimateGas(self, class_name: str) -> int:
        """
        only for testing the contract deploy gas requirement
        :param class_name:
        :return:
        """
        # estimate_gas
        solc_artifact = SolWeb3Tool()
        solc_artifact.setBasePath(self.base_path)
        solc_artifact = solc_artifact.GetCodeClassFromBuild(class_name)
        nr = self.w3.eth.contract(abi=solc_artifact.abi, bytecode=solc_artifact.bin)
        gas_est_amount = nr.constructor().estimateGas()
        price = self.w3.eth.generate_gas_price()
        # source: https://ethereum.stackexchange.com/questions/84943/what-is-the-equivalent-of-buildtransaction-of-web3py-in-web3js
        print(f"Price: {price}")
        return gas_est_amount

    def OverrideGasConfig(self, gas: int, gas_price: int) -> None:
        """
        the override the configuration for the gas amount and the gas price
        :param gas: int
        :param gas_price: int
        :return: NONE
        """
        self.network_cfg.gas = gas
        self.network_cfg.gasPrice = gas_price

    def OverrideChainConfig(self, one: int, wait: int) -> None:
        """
        Lets have the configuration done now.
        :param one: ONE coin to measure
        :param wait: the waiting time from each block confirmation
        :return:
        """
        self.network_cfg.wait_time = wait
        self.network_cfg.one = one

    @property
    def gas(self) -> int:
        return self.network_cfg.gas

    @property
    def gasPrice(self) -> int:
        return self.network_cfg.gasPrice

    @property
    def one(self) -> int:
        """
        ONE platform coin will be decoded to be...
        :return: int
        """
        return self.network_cfg.one

    @property
    def waitSec(self) -> int:
        return self.network_cfg.wait_time

    @property
    def LinkVRFHashKey(self) -> str:
        if self.network_cfg.link_keyhash is None:
            raise ValueError("Link VRF Hash Key is endorsed on this network")
        else:
            return self.network_cfg.link_keyhash

    @property
    def LinkVRFCoordinator(self) -> str:
        if self.network_cfg.link_vrf_coordinator is None:
            raise ValueError("Link VRF is endorsed on this network")
        else:
            return self.network_cfg.link_vrf_coordinator

    @property
    def LinkTokenAddress(self) -> str:
        if self.network_cfg.link_token is None:
            raise ValueError("Link Token is endorsed on this network")
        else:
            return self.network_cfg.link_token

    def _checkErrorForTxReceipt(self, receipt: any, class_name: str, jsonfile: str):

        if "contractAddress" not in receipt:
            print(f"⚠️ Error from deploy contract and no valid address found for {class_name}.")
            raise InvalidAddress

        if "transactionHash" not in receipt:
            print(f"⚠️ The deployment is failed because there is no valid address found from {class_name}. Please check for internal errors from deployment has {receipt.transactionHash}")
            raise InvalidAddress

        hash = str(receipt.transactionHash)
        preaddress = str(receipt.contractAddress)
        if self.isAddress(preaddress) is False:
            print(f"⚠️ The deployment is failed because there is no valid address found from {class_name}. Please check for internal errors from deployment hash from {jsonfile}")
            raise InvalidAddress

    def deploy(self, class_name: str,
               params: list = [],
               gas_price: int = 0,
               gas_limit: int = 0) -> bool:
        """
        This is using the faster way to deploy files by using the specific abi and bin files

        """
        contract_nv = None
        solc_artifact = None
        try:
            solc_artifact = SolWeb3Tool()
            solc_artifact.setBasePath(self.base_path)
            solc_artifact = solc_artifact.GetCodeClassFromBuild(class_name)
            bin = BinOp(solc_artifact.bin, class_name)
            if bin.checkBinForUndeployLib() is True:
                bin.setDebug(True)
                # try to find the needed libraries in address..
                bin.anaylze(self)
                contract_nv = self.w3.eth.contract(abi=solc_artifact.abi, bytecode=bin.GetKnifedBin())
            else:
                contract_nv = self.w3.eth.contract(abi=solc_artifact.abi, bytecode=bin.GetRawBin())

        except FileNotFoundError:
            print("💢 bin or abi file is not found.")
            exit(0)
        except FoundUndeployedLibraries:
            exit(0)
        except ContractLogicError as e:
            print(f"💢 Contract error {e}")
            exit(0)

        try:
            gasprice = self.gasPrice if gas_price == 0 else gas_price
            gas = self.gas if gas_limit == 0 else gas_limit
            if len(params) > 0:
                _transaction = contract_nv.constructor(*params).buildTransaction({
                    "gasPrice": gasprice,
                    "gas": gas
                })
            else:
                _transaction = contract_nv.constructor().buildTransaction({
                    "gasPrice": gasprice,
                    "gas": gas
                })

            _transaction['nonce'] = self.w3.eth.getTransactionCount(self.accountAddr)
            _transaction['to'] = None
            # _transaction['gas'] = self.gas if gas_limit == 0 else gas_limit
            # _transaction['gasPrice'] = self.gasPrice if gas_price == 0 else gas_price
            # _transaction['gas'] = 2200000000,
            print("ok --- ", _transaction)
            # Get correct transaction nonce for sender from the node
            print(f"========🖍 Signing {class_name}, gas:{_transaction['gas']}, price:{_transaction['gasPrice']} ...")
            signed = self.w3.eth.account.sign_transaction(_transaction)

            txHash = self.w3.eth.sendRawTransaction(signed.rawTransaction)
            # print(f"Contract '{class_name}' deployed; Waiting to transaction receipt")
            print(f"========Wait for Block Confirmation - {class_name} ☕️")
            tx_receipt = self.w3.eth.waitForTransactionReceipt(txHash)
            print("========TX Pre-Result ✅")
            print(tx_receipt)
            print(f"========Broadcast Result ✅ -> {Paths.showCurrentDeployedClass(class_name)}")

            self._checkErrorForTxReceipt(tx_receipt, class_name, Paths.showCurrentDeployedClass(class_name))
            fresh_address = tx_receipt.contractAddress
            self._contract_dict[class_name] = fresh_address

            self._contract_dict["kv_{}".format(class_name)] = dict(
                owner=self.accountAddr,
            )

            print("📦 Address saved to ✅ {} -> {}".format(fresh_address, class_name))
            print(f"🔍 You can check with the explorer for more detail: {Bolors.WARNING} {self.network_cfg.block_explorer}{Bolors.RESET}")
            self.artifact_manager = solc_artifact
            solc_artifact.StoreTxResult(tx_receipt, self.pathfinder.classObject(class_name))
            self.complete_deployment()
            return True
        except InvalidAddress:
            return False
        except ContractLogicError as e:
            print(f"Error: {e}")
            return False
        except TimeExhausted:
            print("After 120 seconds, the boardcast block is not in the chain.")
            return False
        except ValueError as te:
            if "code" in te:
                code = int(te["code"])
                if code == -32000:
                    print("NOT ENOUGH GAS - insufficient funds for gas")
                    return False
            print(te)
            return False

    @property
    def __list_key_label(self) -> str:
        return "{}_{}".format(self.list_type, self.last_class)

    @property
    def __kv_label(self) -> str:
        return "kv_{}".format(self.last_class)

    def getAddr(self, keyname: str) -> str:
        """example: TT67rPNwgmpeimvHUMVzFfKsjL9GZ1wGw8"""
        return self._contract_dict.get(keyname)

    def getAllAddress(self) -> dict:
        return self._contract_dict

    def preview_all_addresses(self) -> None:
        print(self._contract_dict)

    def is_deployment(self) -> bool:
        return self.is_deploy

    def ready_io(self, show_address: bool = False):
        """try to load up the file from the existing path"""
        try:
            self._contract_dict = self.pathfinder.LoadDeploymentFile()
            print("📦 Review the loaded deployment data from ... ")
            if show_address:
                self.preview_all_addresses()
        except FileNotFoundError:
            print("💢 Deployment File is not found ...")
        except TypeError as e:
            print(e)

    def setTargetClass(self, classname: str) -> "MiliDoS":
        self.last_class = classname
        return self

    def setTargetListName(self, listname: str) -> "MiliDoS":
        self.list_type = listname
        return self

    def setKV(self, key: str, value: any) -> "MiliDoS":

        if self.__kv_label not in self._contract_dict:
            self._contract_dict[self.__kv_label] = dict()

        self._contract_dict[self.__kv_label][key] = value
        return self

    def hasAddressInList(self, address: str) -> bool:
        if self.__list_key_label not in self._contract_dict:
            return False
        try:
            v = self._contract_dict[self.__list_key_label].index(address)
            return True
        except ValueError:
            return False

    def pushAddress(self, address: str, unique: bool = True) -> bool:
        if self.__list_key_label not in self._contract_dict:
            self._contract_dict[self.__list_key_label] = list()

        if unique is True:
            try:
                found_index = self._contract_dict[self.__list_key_label].index(address)
                return False
            except ValueError:
                self._contract_dict[self.__list_key_label].append(address)
                return True
            except IndexError:
                self._contract_dict[self.__list_key_label].append(address)
                return True
        else:
            self._contract_dict[self.__list_key_label].append(address)
            return True

    def removeAddress(self, address: str) -> bool:
        if self.__list_key_label not in self._contract_dict:
            return False
        self._contract_dict[self.__list_key_label].remove(address)
        return True

    def iterList(self) -> iter:
        if self.__list_key_label not in self._contract_dict:
            raise Exception("there is no list in the map")
        return iter(self._contract_dict[self.__list_key_label])

    def hasList(self) -> bool:
        if self.__list_key_label not in self._contract_dict:
            return False
        return len(self._contract_dict[self.__list_key_label]) > 0

    def hasField(self, key: str) -> bool:
        if self.__kv_label not in self._contract_dict:
            self._contract_dict[self.__kv_label] = dict()

        if key not in self._contract_dict[self.__kv_label]:
            return False
        else:
            return True

    def hasContractName(self, name: str) -> bool:
        return name in self._contract_dict

    def getString(self, key: str) -> str:
        return str(self.getVal(key))

    def getInt(self, key: str) -> int:
        return int(self.getVal(key))

    def getBytesArray(self, key: str) -> bytearray:
        return bytearray(self.getVal(key))

    def getBytes(self, key: str) -> bytes:
        return bytes(self.getVal(key))

    def getFloat(self, key: str) -> float:
        return float(self.getVal(key))

    def getVal(self, key: str) -> any:
        if self.__kv_label not in self._contract_dict:
            self._contract_dict[self.__kv_label] = dict()

        if key in self._contract_dict[self.__kv_label]:
            return self._contract_dict[self.__kv_label][key]

        return ""

    def complete_deployment(self) -> None:
        """store up the deployed contrcat addresses to the local file storage"""
        self.artifact_manager.StoreTxResult(self._contract_dict, self.pathfinder.SaveDeployConfig)

    def SaveConfig(self) -> None:
        self.complete_deployment()
