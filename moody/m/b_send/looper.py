# !/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C0116,W0613
# This program is dedicated to the public domain under the CC0 license.
import math
import time

import pandas as pd
from web3 import exceptions, _utils

from ..b_send import BSend
from ..b_send.basec import BaseBulk, PrintNetworkName
from ..pharaohs import pharaohs
from ...libeb import MiliDoS


class SkeletonLooper(BaseBulk):
    """
    Bulk manager execution now
    @
    """

    def __init__(self, _core: MiliDoS):
        self._c = _core
        super().__init__()
        self.__n = 0
        self.__t = 0
        self.__failures = 0
        self.wait_pause = False
        PrintNetworkName(_core.network_cfg)

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

    def setIterSum(self, t) -> int:
        self.__t = t
        return self.__t

    def Iters(self) -> int:
        return self.__t

    def addFail(self) -> int:
        self.__failures += 1
        return self.__failures

    def addN(self) -> int:
        self.__n += 1
        return self.__n

    def iterN(self) -> int:
        return self.__n

    def resetN(self) -> int:
        self.__n = 0
        return self.__n

    def failure(self, a: str, b: str) -> None:
        pass

    def successTransaction(self, hash: str, name: str) -> None:
        pass


class TestBulkManager(SkeletonLooper):
    """
    Bulk manager execution now
    @
    """

    def __init__(self, dat: list, _core: MiliDoS):
        self.datlist = dat
        super().__init__(_core)
        self._enableContractBatch()

    def prep(self) -> "TestBulkManager":
        self._status_busy = True
        for row in self.datlist:
            address = str(row[0])
            amount = float(row[1])
            enter_digit = int(amount * 10 ** self.decimal)
            if self._is_valid_address(address):
                self._line_read_code(address, amount, enter_digit)
                self.entryAdd(address, enter_digit)
            else:
                self._line_invalid_address(address)
                self.entryErrAdd(address, enter_digit)

        self._batch_preprocess()
        self.PreStatement()

        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getPlatformVal(self) -> int:
        """
        since the entry for python function on SAP is required to be int
        """
        return math.ceil(self.total / self.wei)


class ExcelFeature(SkeletonLooper):

    def __init__(self, filepath, _core: MiliDoS):
        super().__init__(_core)
        self.exeFilepath = filepath
        self.useKeyEng()

    def useKeyChinese(self) -> "ExcelFeature":
        self.kAddress = "提现地址"
        self.kAmount = "提现金额"
        return self

    def useKeyEng(self) -> "ExcelFeature":
        self.kAddress = "address"
        self.kAmount = "amount"
        return self


class ExcelBulkManagerContractTunnel(ExcelFeature):
    """
    using contract on making at least XXX transactions in a batch.
    """

    def __init__(self, filepath, m: MiliDoS):
        super().__init__(filepath, m)
        self._enableContractBatch()

    def failure(self, a: str, b: str) -> None:
        """
        custom failure function and recording
        :param a:
        :param b:
        :return:
        """
        if self._file_logger is not None:
            self._file_logger(f"Batch#{self.iterN()} {a} {b} Failed. ❌ ")
        self.addFail()

    def successTransaction(self, hash: str, name: str) -> None:
        """
        custom success function and the recording
        :param hash:
        :param name:
        :return:
        """
        if self._file_logger is not None:
            self._file_logger(f"Batch#{self.iterN()} hash: {hash} 📤 ")

    def executeTokenTransferOnContractBusTg(
            self,
            express_contract: BSend,
            coin_contract: pharaohs,
            notify=None, errorNotify=None) -> None:
        """


        :param express_contract:contract instance
        :param coin_contract: token contract instance
        :param notify: callback function
        :param errorNotify: callback function

        """
        self._status_busy = True
        coin_address = coin_contract.contract_address
        express_address = express_contract.contract_address
        self.setIterSum(self._batches_count)
        self.resetN()

        if not self._batch_contract:
            self._line_error(errorNotify, "⚠️ Batch contract is not activated")
            return

        if not self._is_valid_address(coin_address):
            self._line_error(errorNotify, f"⚠️ ERC20 is not valid {coin_address}")
            return

        for batch in self._batch:
            try:
                batch_size = len(batch[0])
                total_approval = sum(batch[1])
                _address = batch[0]
                _amount = batch[1]

                print(f"====== result batch len: {len(batch[0])}, approving: {total_approval}")
                balance = coin_contract.balance_of(self._c.accountAddr)

                if balance >= total_approval:
                    coin_contract.EnforceTxReceipt(True)
                    coin_contract.approve(express_address, total_approval)
                else:
                    self._line_error(errorNotify, "⚠️ not enough in the balance")
                    return

                print(f"====== start batch transactions")
                express_contract.onSuccssCallback(self.successTransaction)
                express_contract.onFailCallback(self.failure)
                express_contract.EnforceTxReceipt(True).bulk_send_token(
                    coin_address, _address, _amount, 0
                )

                self.addN()
                self._line_progress(notify)

                if batch_size == self.batch_limit and self.wait_pause:
                    print("====== result bulk_send_token, the next batch will start in 30 seconds")
                    time.sleep(30)
                else:
                    print("====== Now the next wave of token send will start immediately")

            except exceptions.CannotHandleRequest:
                self._line_error(errorNotify, "⚠️ request is not handled")
                return
            except exceptions.TimeExhausted:
                self._line_error(errorNotify, "⚠️ the transaction is not on chain after timeout")
                return
            except _utils.threads.Timeout:
                self._line_error(errorNotify, "⚠️ threads timeout")
                return

        self._status_busy = False

    def prep(self) -> "ExcelBulkManagerContractTunnel":
        """
        counting the excel sheet and filter the data
        :return: This is a chained method
        """
        self._status_busy = True
        # df = pd.read_excel(r'C:\Users\Ron\Desktop\Product List.xlsx')
        data = pd.read_excel(self.exeFilepath)
        # data = pd.read_excel(r'C:\Users\Ron\Desktop\Product List.xlsx')
        df = pd.DataFrame(data, columns=[self.kAddress, self.kAmount])
        for index, row in df.iterrows():

            # trim line
            address = str(row[self.kAddress]).translate(str.maketrans('', '', ' \n\t\r'))
            amount = float(row[self.kAmount])
            enter_digit = int(amount * 10 ** self.decimal)
            if self._is_valid_address(address):
                self._line_read_code(row[self.kAddress], amount, enter_digit)
                self.entryAdd(address, enter_digit)
            else:
                self._line_invalid_address(address)
                self.entryErrAdd(address, enter_digit)
                continue

        self._batch_preprocess()
        self.PreStatement()

        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getSENDTotal(self) -> int:
        return self.total

    def getPlatformVal(self) -> int:
        return int(self.total / self.wei)


class ExcelBulkManagerClassic(ExcelFeature):
    """
    This is the traditional wallet to wallet transaction transfer using the native method
    """

    def __init__(self, filepath, tron):
        super().__init__(filepath, tron)
        self._in_process_address = None
        self._in_process_amount = 0

    def prep(self) -> "ExcelBulkManagerClassic":
        """
        counting the excel sheet and filter the data
        :return: This is a chained method
        """
        self._status_busy = True
        # df = pd.read_excel(r'C:\Users\Ron\Desktop\Product List.xlsx')
        data = pd.read_excel(self.exeFilepath)
        # data = pd.read_excel(r'C:\Users\Ron\Desktop\Product List.xlsx')
        df = pd.DataFrame(data, columns=[self.kAddress, self.kAmount])
        for index, row in df.iterrows():
            # trim line
            address = str(row[self.kAddress]).translate(str.maketrans('', '', ' \n\t\r'))
            amount = float(row[self.kAmount])
            enter_digit = int(amount * 10 ** self.decimal)
            try:
                if self._is_valid_address(address):
                    self._line_color_code(address, amount, enter_digit)
                    self.entryAdd(address, enter_digit)
                else:
                    self._line_color_invalid_address(address, enter_digit)
                    self.entryErrAdd(address, enter_digit)

            except ValueError as h:
                self._line_color_invalid_address(address, enter_digit, h)
                self.entryErrAdd(address, enter_digit)

        self.PreStatement()

        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getSENDTotal(self) -> int:
        return self.total

    def executeTokenDistribution(self, token: pharaohs, notify=None):

        self.resetN()
        self.setIterSum(self.transaction_count)
        self._status_busy = True

        if len(self.list_amount) != len(self.list_address):
            print("error in checking the length of transaction list")
            return

        for address in self.list_address:
            token.transfer(address, self.list_amount[self.iterN()])
            self.addN()
            self._line_progress(notify)

        self._status_busy = False

    def failure(self, a: str, b: str) -> None:
        if self._file_logger is not None:
            self._file_logger(f"#{self.iterN()} {a} {b} Failed. ❌ ")
        self.addFail()

    def successTransaction(self, hash: str, name: str) -> None:
        if self._file_logger is not None:
            self._file_logger(f"#{self.iterN()} {hash} OK, {self._in_process_address} {self._in_process_amount} 📤 ")

    def executeTokenTransferDistributionTg(self, token: pharaohs, notify=None, errorNotify=None) -> None:
        """
         Limitation: https://core.telegram.org/bots/faq#my-bot-is-hitting-limits-how-do-i-avoid-this
         When sending messages inside a particular chat, avoid sending more than one message per second. We may allow short bursts that go over this limit, but eventually you'll begin receiving 429 errors.
         If you're sending bulk notifications to multiple users, the API will not allow more than 30 messages per second or so. Consider spreading out notifications over large intervals of 8—12 hours for best results.
         Also note that your bot will not be able to send more than 20 messages per minute to the same group.

         This is a block function and it will take some time to complete

        :param token: token instance
        :param notify: callback function
        :param errorNotify: callback function
        """
        self.resetN()
        self.setIterSum(len(self.list_address))
        self._status_busy = True

        _timestamp = self.nowSec
        if len(self.list_amount) != self.Iters():
            errorNotify("error in checking the length of transaction list")
            return

        token.onSuccssCallback(self.successTransaction)
        token.onFailCallback(self.failure)

        try:

            for address in self.list_address:
                self._in_process_address = address
                report_amount = self.list_amount[self.iterN()]
                self._in_process_amount = report_amount
                token.transfer(address, report_amount)
                self.addN()
                _dela = self.nowSec
                if notify is not None:
                    if _dela > _timestamp + 5 or self.iterN() >= self.Iters():
                        _timestamp = self.nowSec
                        self._line_progress(notify)

                time.sleep(0.5)

        except ValueError:
            errorNotify("Value error. unknown error")
            return

        self._status_busy = False
