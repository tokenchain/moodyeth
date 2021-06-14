import codecs
import json
import os
import subprocess
import time
from threading import Lock
from typing import List, Tuple, Optional

from hexbytes import HexBytes
from web3 import Web3, HTTPProvider
from web3.contract import Contract as Web3Contract
from web3.datastructures import AttributeDict
from web3.exceptions import TransactionNotFound
from web3.logs import DISCARD
from web3.middleware import geth_poa_middleware
from web3.types import BlockData

from moody.buildercompile.remotecompile import BuildRemoteLinuxCommand
from moody.buildercompile.transpile import BuildLang
from moody.conf import Config
from moody.paths import Paths


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


class MiliDoS:
    """
    wrap the web3 into the package
    """

    def __init__(self, netconfig: Config):
        self.base_path = ""
        self.accountAddr = None
        self.pathfinder = None
        self.artifact_manager = None
        self.is_deploy = False
        self.last_class = ""
        self.list_type = "list_address"
        self._contract_dict = dict()
        self.network_cfg = netconfig
        self.w3 = web3_provider(netconfig.rpc_url)
        result = self.w3.isConnected()
        print(f"is now connected to {netconfig.network_name}: {result}")
        if not result:
            exit(0)

    def withPOA(self) -> "MiliDoS":
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        return self

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

    def setWorkspace(self, path: str) -> "MiliDoS":
        self.base_path = path
        self.pathfinder = Paths(path).setDefaultPath().Network(self.network_cfg.network_name)
        return self

    def remoteCompile(self, to_compile_contract_list: list, ver: str) -> "MiliDoS":
        self.pathfinder.setSolVersion(ver)
        BuildRemoteLinuxCommand(self.pathfinder, to_compile_contract_list)
        return self

    def localTranspile(self, to_compile_contract_list: list, ver: str) -> "MiliDoS":
        BuildLang(self.pathfinder, to_compile_contract_list)
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

    def Auth(self, priok: str) -> "MiliDoS":
        # f"0x{priok}"
        keyoo = self.w3.eth.account.from_key(f"0x{priok}")
        # self.w3.eth.defaultAccount = keyoo.address
        self.w3.eth.account = keyoo
        self.accountAddr = keyoo.address
        print(keyoo.address)
        return self

    def deploy(self, class_name: str,
               params: list = [],
               fee: int = 10 ** 9,
               percent: int = 1) -> None:
        """
        This is using the faster way to deploy files by using the specific abi and bin files

        """

        solc_artifact = SolWeb3Tool()
        solc_artifact.setBasePath(self.base_path)
        solc_artifact = solc_artifact.GetCodeClassFromBuild(class_name)
        nr = self.w3.eth.contract(abi=solc_artifact.abi, bytecode=solc_artifact.bin)
        _transaction = nr.constructor().buildTransaction()

        _transaction['nonce'] = self.w3.eth.getTransactionCount(self.accountAddr)
        _transaction['to'] = None
        # Get correct transaction nonce for sender from the node
        print("======== Signing {} ✅ ...".format(class_name))
        signed = self.w3.eth.account.sign_transaction(_transaction)
        txHash = self.w3.eth.sendRawTransaction(signed.rawTransaction)
        # print(f"Contract '{class_name}' deployed; Waiting to transaction receipt")
        tx_receipt = self.w3.eth.waitForTransactionReceipt(txHash)
        print("======== TX Result ✅")
        print(tx_receipt)

        print("======== Broadcast Result ✅ -> {}".format(Paths.showCurrentDeployedClass(class_name)))

        if "contractAddress" not in tx_receipt:
            print("error from deploy contract")
            exit(1)

        self._contract_dict[class_name] = tx_receipt.contractAddress
        self._contract_dict["kv_{}".format(class_name)] = dict(
            owner="",
        )
        print("======== address saved to ✅ {} -> {}".format(tx_receipt.contractAddress, class_name))
        print("You can check with the explorer for more detail: {}".format(self.network_cfg.block_explorer))
        self.artifact_manager = solc_artifact
        solc_artifact.StoreTxResult(tx_receipt, self.pathfinder.classObject(class_name))
        self.complete_deployment()

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
            print("==== 🛄 data is prepared and it is ready now.. ")
            if show_address:
                self.preview_all_addresses()
        except ValueError:
            pass
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
