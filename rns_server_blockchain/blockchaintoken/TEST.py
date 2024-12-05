##############################################################################################################
#
# Copyright (c) 2024 Sebastian Obele  /  obele.eu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This software uses the following software-parts:
# Reticulum  /  Copyright (c) 2016-2022 Mark Qvist  /  unsigned.io  /  MIT License
#
##############################################################################################################


#### TEST ####
import time
import os
import RNS.vendor.umsgpack as msgpack
from Crypto.Hash import HMAC


class BlockchainTokenTEST():
    AMOUNT = 100*100000000
    FEE    = 0
    NONCE  = 0

    def __init__(self, owner, name):
        self.owner = owner
        self.name = name

        self.token = {
            "TEST": {},
        }

        self.data = None
        self.data_changed = False


    #################################################
    # Accounts                                      #
    #################################################


    def accounts_add(self, token, data):
        if "phrase" in data:
            phrase = data["phrase"].strip()

        account_id = HMAC.new(phrase.encode("utf8")).hexdigest()

        if account_id not in self.data["accounts"]:
            self.data["accounts"][account_id] = {
                "balance": self.AMOUNT,
                "nonce":   self.NONCE
            }

            if self.AMOUNT > 0:
                self.data["transactions"][self.owner.generate_id(64)] = {
                    "amount":  self.AMOUNT,
                    "comment": "Initial test money",
                    "dest":    account_id,
                    "fee":     self.FEE,
                    "source":  self.data["uid"],
                    "ts":      int(time.time())
                }

            self.data_changed = True

        result = {
            "account_id": account_id,
            "data": {
            },
            "state":      self.owner.ACCOUNT_STATE_SUCCESSFULL
        }

        return result


    def accounts_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def accounts_get(self, token, account_id):
        if account_id in self.data["accounts"]:
            result = {
                "account_id": account_id,
                "balance":    self.data["accounts"][account_id]["balance"],
                "nonce":      self.data["accounts"][account_id]["nonce"]
            }
        else:
            result = {
                "account_id": account_id,
                "balance":    0,
                "nonce":      0
            }

        return result


    def accounts_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")


    #################################################
    # API                                           #
    #################################################


    def api_delete(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_get(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_patch(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_post(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_put(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    #################################################
    # Blocks                                        #
    #################################################


    def blocks_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def blocks_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")


    #################################################
    # Connection                                    #
    #################################################


    def connection_response_start(self, token):
        if not self.data:
            self.data_load()


    def connection_response_stop(self, token):
        if self.data_changed:
            self.data_changed = False
            self.data_save()


    #################################################
    # Delegates                                     #
    #################################################


    def delegates_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def delegates_get(self, token):
        result = {}

        return result


    def delegates_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")


    #################################################
    # Infos                                         #
    #################################################


    def infos_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def infos_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")


    #################################################
    # Transactions                                  #
    #################################################


    def transactions_add(self, token, account_id, account_data, transaction_data):
        if account_id not in self.data["accounts"]:
            raise ValueError("Source account not exist")

        if transaction_data["dest"] not in self.data["accounts"]:
            raise ValueError("Destination account not exist")

        if transaction_data["nonce"] != self.data["accounts"][account_id]["nonce"]:
            raise ValueError("Nonce invalid")

        fee = transaction_data["fee"] if "fee" in transaction_data else self.FEE

        if self.data["accounts"][account_id]["balance"] < (transaction_data["amount"]+fee):
            raise ValueError("Balance not sufficient")

        transaction_id = self.owner.generate_id(64)

        self.data["transactions"][transaction_id] = {
                "amount":  transaction_data["amount"],
                "comment": transaction_data["comment"],
                "dest":    transaction_data["dest"],
                "fee":     fee,
                "source":  account_id,
                "ts":      int(time.time())
        }

        self.data["accounts"][transaction_data["dest"]]["balance"] += transaction_data["amount"]
        self.data["accounts"][account_id]["balance"] -= (transaction_data["amount"]+fee)
        self.data["accounts"][account_id]["nonce"] += 1

        self.data_changed = True

        result = {
            "transaction_id": transaction_id
        }

        return result


    def transactions_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def transactions_get(self, token, account_id, ts):
        result = {}

        for transaction_id, transaction in self.data["transactions"].items():
            if (transaction["source"] == account_id or transaction["dest"] == account_id) and transaction["ts"] > ts:
                result[transaction_id] = {
                    "amount":  transaction["amount"],
                    "comment": transaction["comment"],
                    "dest":    transaction["dest"],
                    "fee":     transaction["fee"],
                    "source":  transaction["source"],
                    "ts":      transaction["ts"]
                }

        return result


    def transactions_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")


    #################################################
    # Helpers - Data                                #
    #################################################


    def data_load(self):
        try:
            file = self.owner.storage_path+"/"+self.name+".data"
            if os.path.isfile(file):
                fh = open(file, "rb")
                self.data = msgpack.unpackb(fh.read())
                fh.close()
            else:
                self.data_default()
                fh = open(self.owner.storage_path+"/"+self.name+".data", "wb")
                fh.write(msgpack.packb(self.data))
                fh.close()
        except:
            self.data_default()


    def data_save(self):
        try:
            file = self.owner.storage_path+"/"+self.name+".data"
            fh = open(self.owner.storage_path+"/"+self.name+".data", "wb")
            fh.write(msgpack.packb(self.data))
            fh.close()
        except:
            pass


    def data_default(self):
        self.data = {}
        self.data["accounts"]     = {}
        self.data["transactions"] = {}
        self.data["uid"]          = self.owner.generate_id(32)
