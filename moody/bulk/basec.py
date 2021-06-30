# !/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C0116,W0613
# This program is dedicated to the public domain under the CC0 license.
from web3 import Web3

from moody import conf


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR


def yes_or_no(question):
    """Simple Yes/No Function."""
    prompt = f'{question} ? (y/n): '
    answer = input(prompt).strip().lower()
    if answer not in ['y', 'n']:
        print("========================================")
        print(f'{answer} is invalid, please try again...')
        return yes_or_no(question)
    if answer == 'y':
        return True
    return False


def PrintNetworkName(network_conf: conf):
    print(f"You are now using network {bcolors.WARNING}{str(network_conf.network_name).upper()}{bcolors.RESET}")


def WriteFile(content, filename: str):
    fo = open(filename, "w")
    fo.write(content)
    fo.close()


class BaseBulk:
    wei = 1000000000000000000
    token_symbol = "xDai"
    fee_set = 9

    def __init__(self):
        self.list_address = list()
        self.list_amount = list()
        self.err_address = list()
        self.err_amount = list()
        self.decimal = 6
        self.total = 0
        self.err_total = 0
        self.transaction_count = 0
        self.processed_count = 0
        self.logger = None
        self.checker_log = None
        self._status_busy = False
        self._logfile = None

    def withDecimal(self, dec: int) -> "BaseBulk":
        self.decimal = dec
        return self

    @property
    def isBusy(self) -> bool:
        return self._status_busy

    def prep(self) -> None:
        pass

    def getSENDAddresses(self) -> list:
        pass

    def getSENDAmountBalances(self) -> list:
        pass

    def getPlatformVal(self) -> int:
        return int(self.total / BaseBulk.wei)

    def getSENDTotal(self) -> int:
        return self.total

    def getPlatformErrVal(self) -> int:
        return int(self.err_total / BaseBulk.wei)

    def entryAdd(self, address: str, amount: int):
        """
        adding the validate transaction count and
        the balance of total transaction
        """
        self.list_address.append(address)
        self.list_amount.append(amount)
        self.total += int(amount)
        self.transaction_count = self.transaction_count + 1

    def entryErrAdd(self, address: str, amount: int):
        self.err_address.append(address)
        self.err_amount.append(amount)
        self.err_total += int(amount)

    def calculation(self) -> float:
        return int(self.total / BaseBulk.wei)

    def ListErrors(self):
        j = 0
        for h in self.err_address:
            print(f"error {bcolors.FAIL}{h}{bcolors.RESET} -> {bcolors.FAIL}{self.err_amount[j]}{bcolors.RESET}")
            j = j + 1

    def ListErrorsLogger(self):
        j = 0
        for h in self.err_address:
            self.logger(f"❌ {h} -> {self.err_amount[j]}")
            j = j + 1

    def ListErrorsLoggerChecker(self):
        j = 0
        for h in self.err_address:
            self.checker_log(f"❌ {h} -> {self.err_amount[j]}")
            j = j + 1

    def _line_invalid_address(self, error_address: str) -> None:
        print(f">>>> {bcolors.FAIL}{error_address}{bcolors.RESET}")

    def _line_color_invalid_address(self, error_address: str, digit: int, h: any = None) -> None:
        if h is not None:
            print(f">>>> {bcolors.FAIL}{error_address} > {digit}{bcolors.RESET}, {h}")
        else:
            print(f">>>> {bcolors.FAIL}{error_address} > {digit}{bcolors.RESET}")

    def _line_read_code(self, address: str, amount: float, digit: int) -> None:
        print(f"{address}, read {amount} decimalcode ~> {digit}")

    def _line_color_code(self, address: str, amount: float, digit: int):
        print(f"{address}, read {bcolors.WARNING}{amount}{bcolors.RESET} decimal code> {digit}")

    def _is_valid_address(self, h: str) -> bool:
        if not Web3.isAddress(h):
            return False
        if not Web3.isChecksumAddress(h):
            return False
        return True

    def PreStatementTg(self):
        if not self.checker_log:
            return
        transaction_reserve = self.transaction_count * self.fee_set
        self.checker_log("===============================================")
        self.checker_log(f"Grand total:{self.getPlatformVal()}, decimal code> {self.total}")
        self.checker_log(f"Error total:{self.getPlatformErrVal()}, decimal code> {self.err_total}")
        self.checker_log(f"Trn count:{self.transaction_count}, Est. fee> {transaction_reserve} {self.token_symbol}")
        self.checker_log("===============================================")
        self.ListErrorsLoggerChecker()
        self.checker_log("===============================================")

    def PreStatement(self) -> None:
        transaction_reserve = self.transaction_count * self.fee_set
        if self.logger == None:
            print("===============================================")
            print(f"Grand total:{bcolors.OK}{self.getPlatformVal()}{bcolors.RESET}, decimal code> {self.total}")
            print(f"Error total:{bcolors.FAIL}{self.getPlatformErrVal()}{bcolors.RESET}, decimal code> {self.err_total}")
            print(f"Trn count:{bcolors.OK}{self.transaction_count}{bcolors.RESET}, Est. fee> {bcolors.WARNING}{transaction_reserve}{bcolors.RESET} {self.token_symbol}")
            print("===============================================")
            self.ListErrors()
            print("===============================================")
            r = yes_or_no("Do you confirm the above data?")
            if not r:
                print("let make some adjustment and be sure the data is correct.")
                exit(0)
        else:
            self.logger("===============================================")
            self.logger(f"Grand total:{self.getPlatformVal()}, decimal code> {self.total}")
            self.logger(f"Error total:{self.getPlatformErrVal()}, decimal code> {self.err_total}")
            self.logger(f"Trn count:{self.transaction_count}, Est. fee> {transaction_reserve} {self.token_symbol}")
            self.logger("===============================================")
            self.ListErrorsLogger()
            self.logger("===============================================")
        self._status_busy = False

    def setLogger(self, logger) -> None:
        self.logger = logger

    def setLogFile(self, outputfile: str) -> None:
        self._logfile = outputfile
        WriteFile("", outputfile)

    @property
    def getLogFileLocation(self) -> str:
        return self._logfile

    def appendLogLine(self, line: str) -> None:
        file_object = open(self._logfile, 'a')
        file_object.write("{}\n".format(line))
        file_object.close()

    def setCheckLogger(self, check_save) -> None:
        self.checker_log = check_save
