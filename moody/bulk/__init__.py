# !/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C0116,W0613
# This program is dedicated to the public domain under the CC0 license.
import math
import time

import pandas as pd

from .basec import BaseBulk, PrintNetworkName, bcolors
from ..libeb import MiliDoS
from ..m.erc20 import Ori20


class TestBulkManager(BaseBulk):
    """
    Bulk manager execution now
    @
    """

    def __init__(self, dat: list, mHold: MiliDoS):
        self.datlist = dat
        self.tron = mHold
        PrintNetworkName(mHold.network_cfg)
        super().__init__()

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

        self.PreStatement()
        self.PreStatementTg()
        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getPlatformVal(self) -> int:
        """
        since the entry for python function on SAP is required to be int
        """
        return math.ceil(self.total / TestBulkManager.wei)


class ExcelBasic(BaseBulk):

    def __init__(self, filepath, network_conf):
        super().__init__()
        PrintNetworkName(network_conf)
        self.exeFilepath = filepath
        self.tron = network_conf
        self.kAddress = "address"
        self.kAmount = "amount"

    def useKeyChinese(self) -> "ExcelBasic":
        self.kAddress = "提现地址"
        self.kAmount = "提现金额"
        return self

    def useKeyEng(self) -> "ExcelBasic":
        self.kAddress = "address"
        self.kAmount = "amount"
        return self


class ExcelBulkManager(ExcelBasic):

    def __init__(self, filepath, tron):
        super().__init__(filepath, tron)

    def prep(self) -> "ExcelBulkManager":
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

        self.PreStatement()
        self.PreStatementTg()

        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getSENDTotal(self) -> int:
        return self.total

    def getPlatformVal(self) -> int:
        return int(self.total / TestBulkManager.wei)


class ExcelBulkManagerClassic(ExcelBasic):

    def __init__(self, filepath, tron):
        super().__init__(filepath, tron)

    def prep(self) -> "ExcelBulkManagerClassic":
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
        self.PreStatementTg()

        return self

    def getSENDAddresses(self) -> list:
        return self.list_address

    def getSENDAmountBalances(self) -> list:
        return self.list_amount

    def getSENDTotal(self) -> int:
        return self.total

    def executeTokenDistribution(self, token: Ori20, notify=None):
        v = 0
        self._status_busy = True

        if len(self.list_amount) != len(self.list_address):
            print("error in checking the length of transaction list")
            return

        for address in self.list_address:
            token.transfer(address, self.list_amount[v])
            v += 1
            if notify is not None:
                self.processed_count = v
                perc = "{0:.0f}%".format(v / self.transaction_count * 100)
                notify(v, self.transaction_count, perc)

        self._status_busy = False

    @property
    def nowSec(self) -> int:
        from datetime import datetime
        import time
        return int(time.mktime(datetime.today().timetuple()))

    def executeTokenTransferDistributionTg(self, token: Ori20, notify=None, errorNotify=None):
        """
         limitation: https://core.telegram.org/bots/faq#my-bot-is-hitting-limits-how-do-i-avoid-this
         When sending messages inside a particular chat, avoid sending more than one message per second. We may allow short bursts that go over this limit, but eventually you'll begin receiving 429 errors.
         If you're sending bulk notifications to multiple users, the API will not allow more than 30 messages per second or so. Consider spreading out notifications over large intervals of 8—12 hours for best results.
         Also note that your bot will not be able to send more than 20 messages per minute to the same group.

         errors from the operation

        """
        v = 0
        self._status_busy = True

        _timestamp = self.nowSec
        if len(self.list_amount) != len(self.list_address):
            errorNotify("error in checking the length of transaction list")
            return
        try:

            for address in self.list_address:
                recipient = address
                report_amount = self.list_amount[v]
                token.transfer(recipient, report_amount)
                v += 1
                _dela = self.nowSec
                if notify is not None and _dela > _timestamp + 5:
                    _timestamp = self.nowSec
                    self.processed_count = v
                    _perc = "{0:.0f}%".format(v / self.transaction_count * 100)
                    notify(v, self.transaction_count, _perc)

                if self.logger is not None:
                    self.logger(f"#{v} {recipient} {report_amount} 📤 ")

                time.sleep(0.5)



        except ValueError:
            errorNotify("Value error. unknown error")
            return

        self._status_busy = False
