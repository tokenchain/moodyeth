# !/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C0116,W0613
# This program is dedicated to the public domain under the CC0 license.
import math

from web3 import Web3

from ... import conf, Bolors


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
    print(f"You are now using network {Bolors.WARNING}{str(network_conf.network_name).upper()}{Bolors.RESET}")


def WriteFile(content, filename: str):
    fo = open(filename, "w")
    fo.write(content)
    fo.close()


class BaseBulk:
    wei = 1000000000000000000
    token_symbol = "xDai"
    fee_set = 9

    def __init__(self):
        self.batch_limit = 250
        self.list_address = list()
        self.list_amount = list()
        self.err_address = list()
        self.err_amount = list()
        self.decimal = 6
        self.total = 0
        self.err_total = 0
        self.transaction_count = 0
        self.processed_count = 0
        self._gas_fee = 0

        self._file_logger = None
        self._tg_logger = None
        self._status_busy = False
        self._program_override = False
        self._logfile = None
        self._batch_contract = False
        self._batch = []
        self._batches_count = 0

    def _enableContractBatch(self):
        self._batch_contract = True

    def _newBatchSlots(self):
        self._batch = []

    def weiUpdate(self, decimal: int) -> "BaseBulk":
        """
        only update this for the change wei size of the native token.
        :param decimal: the size of wei decimal in native token
        :return:
        """
        self.wei = 10 ** decimal
        return self

    def batchLimitUpdate(self, total_count: int) -> "BaseBulk":
        self.batch_limit = total_count

        if total_count > 255:
            self.batch_limit = 255
            print("⚠️ You cannot set the count total to be more than 255")
        if total_count < 10:
            self.batch_limit = 10
            print("⚠️ You cannot set the count total to be less than 10")

        return self

    def symbolUpdate(self, coin_symbol: str) -> "BaseBulk":
        self.token_symbol = coin_symbol
        return self

    def withDecimal(self, dec: int) -> "BaseBulk":
        """
        the size of the token decimal
        :param dec: number of decimal
        :return:
        """
        self.decimal = dec
        return self

    def setPerTransactionFee(self, fee: float) -> "BaseBulk":
        self.fee_set = fee
        return self

    @property
    def getGasFeeCode(self) -> int:
        return int(self._gas_fee * BaseBulk.wei)

    @property
    def CountAllValidTrans(self) -> int:
        return self.transaction_count

    @property
    def nowSec(self) -> int:
        from datetime import datetime
        import time
        return int(time.mktime(datetime.today().timetuple()))

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

    def _error_too_many(self) -> bool:
        return len(self.err_address) > 50

    def ListErrors(self):
        j = 0
        for h in self.err_address:
            print(f"error {Bolors.FAIL}{h}{Bolors.RESET} -> {Bolors.FAIL}{self.err_amount[j]}{Bolors.RESET}")
            j = j + 1

    def ListErrorsLogger(self):
        j = 0
        for h in self.err_address:
            self._file_logger(f"❌ {h} -> {self.err_amount[j]}")
            j = j + 1

    def ListErrorsLoggerChecker(self):
        if self._error_too_many():
            self._tg_logger("Too much errors. cannot show them all")
            return

        j = 0
        for h in self.err_address:
            self._tg_logger(f"❌ {h} -> {self.err_amount[j]}")
            j = j + 1

    def _line_invalid_address(self, error_address: str) -> None:
        print(f">>>> {Bolors.FAIL}{error_address}{Bolors.RESET}")

    def _line_color_invalid_address(self, error_address: str, digit: int, h: any = None) -> None:
        if h is not None:
            print(f">>>> {Bolors.FAIL}{error_address} > {digit}{Bolors.RESET}, {h}")
        else:
            print(f">>>> {Bolors.FAIL}{error_address} > {digit}{Bolors.RESET}")

    def _line_read_code(self, address: str, amount: float, digit: int) -> None:
        print(f"{address}, read {amount} decimalcode ~> {digit}")

    def _line_color_code(self, address: str, amount: float, digit: int):
        print(f"{address}, read {Bolors.WARNING}{amount}{Bolors.RESET} decimal code> {digit}")

    def _is_valid_address(self, h: str) -> bool:
        if not Web3.isAddress(h):
            return False
        if not Web3.isChecksumAddress(h):
            return False
        return True

    def _batch_preprocess(self):
        if not self._batch_contract:
            return

        batches = math.ceil(self.transaction_count / self.batch_limit)
        batchslots = list()

        w = 0
        for i in range(batches):
            k = 0
            addresses = []
            amountcode = []
            while k < self.batch_limit and w < self.transaction_count:
                c_address = self.list_address[w]
                addresses.append(c_address)
                c_amount_code = self.list_amount[w]
                amountcode.append(c_amount_code)
                k += 1
                w += 1

            batchslots.append([addresses, amountcode])

        print(f"===== batch process - {Bolors.OK}{batches}{Bolors.RESET}")
        self._batch = batchslots
        self._batches_count = batches

    def PreStatement(self) -> None:
        transaction_reserve = self.transaction_count * self.fee_set
        self._gas_fee = transaction_reserve

        if self._file_logger is not None:
            self._file_logger("===============================================")
            self._file_logger(f"Grand total:{self.getPlatformVal()}, decimal code> {self.total}")
            self._file_logger(f"Error total:{self.getPlatformErrVal()}, decimal code> {self.err_total}")
            self._file_logger(f"Trn count:{self.transaction_count}, Est. fee> {transaction_reserve} {self.token_symbol}")

            if self._batch_contract:
                self._file_logger(f"Batch count: {self._batches_count}")

            self._file_logger("===============================================")
            self.ListErrorsLogger()
            self._file_logger("===============================================")

        if self._tg_logger is not None:
            self._tg_logger("===============================================")
            self._tg_logger(f"Grand total:{self.getPlatformVal()}, decimal code> {self.total}")
            self._tg_logger(f"Error total:{self.getPlatformErrVal()}, decimal code> {self.err_total}")
            self._tg_logger(f"Trn count:{self.transaction_count}, Est. fee> {transaction_reserve} {self.token_symbol}")

            if self._batch_contract:
                self._tg_logger(f"Batch count: {self._batches_count}")

            self._tg_logger("===============================================")
            self.ListErrorsLoggerChecker()
            self._tg_logger("===============================================")

        if not self._program_override:
            print("===============================================")
            print(f"Grand total:{Bolors.OK}{self.getPlatformVal()}{Bolors.RESET}, decimal code> {self.total}")
            print(f"Error total:{Bolors.FAIL}{self.getPlatformErrVal()}{Bolors.RESET}, decimal code> {self.err_total}")
            print(f"Trn count:{Bolors.OK}{self.transaction_count}{Bolors.RESET}, Est. fee> {Bolors.WARNING}{transaction_reserve}{Bolors.RESET} {self.token_symbol}")

            if self._batch_contract:
                print(f"Batch count: {Bolors.OK}{self._batches_count}{Bolors.RESET}")

            print("===============================================")
            self.ListErrors()
            print("===============================================")
            r = yes_or_no("Do you confirm the above data?")
            if not r:
                print("let make some adjustment and be sure the data is correct.")
                exit(0)

        self._status_busy = False

    def setLogger(self, logger_to_file) -> None:
        self._file_logger = logger_to_file

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
        self._tg_logger = check_save

    def setProgramUseOnly(self):
        self._program_override = True


class LooperBulk(BaseBulk):
    """
    Bulk manager execution now
    @
    """

    def __init__(self, mHold: MiliDoS):
        self.dos = mHold
        PrintNetworkName(mHold.network_cfg)
        super().__init__()
        self.__n = 0
        self.__t = 0
        self.__failures = 0
        self.wait_pause = False

    def failureCounts(self) -> int:
        return self.__failures

    def ActivateWaitPause(self):
        self.wait_pause = True

    def _line_progress(self, notify=None) -> None:
        if notify is None:
            return
        else:
            perc = "{0:.0f}%".format(self.__n / self.__t * 100)
            notify(self.__n, self.__t, perc)

    def _line_error(self, errorNotify=None, info: str = "") -> None:
        if errorNotify is None:
            print(f"======{info}")
        else:
            errorNotify(info)

    def failure(self, a: str, b: str) -> None:
        pass

    def successTransaction(self, hash: str, name: str) -> None:
        pass