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


#### Hydraledger ####
# Install:
#  sudo apt install curl
#  sudo apt install pkg-config
#  sudo apt install libssl-dev
#  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#  . "$HOME/.cargo/env"
#  pip3 install pycrypto
#  pip3 install maturin
#  pip3 install iop-python
#  pip3 install requests
import iop_python as sdk
from Crypto.Hash import HMAC

import json
import requests
import time
import threading


class BlockchainTokenHYD():
    DEFAULT_CONFIG = '''
[main]
server_discovery_interval = 720 # Minutes
server_check_interval = 30 # Minutes
server_timeout = 2 # Seconds
server_api_limit = 100

[HYD]
server = 185.163.117.42 # Current selected server
network = mainnet # Network
account = 0 # Account index
idx = 0 # Account index
password = unlockPassword # Unlock password

[DHYD]
server = 35.240.62.119 # Current selected server
network = devnet # Network
account = 0 # Account index
idx = 0 # Account index
password = unlockPassword # Unlock password

[THYD]
server =  # Current selected server
network = testnet # Network
account = 0 # Account index
idx = 0 # Account index
password = unlockPassword # Unlock password

[HYD_server]
185.163.117.42
152.89.107.233
89.58.14.134
89.58.30.214
185.163.119.101
185.163.119.78
85.235.66.112
5.252.227.153
46.38.251.189
195.90.219.66
89.58.40.236
explorer.hydraledger.tech

[DHYD_server]
35.240.62.119
35.204.124.143
35.228.196.114
34.68.118.161
34.87.3.205
dev.explorer.hydraledger.tech

[THYD_server]
test.explorer.hydraledger.tech
'''


    def __init__(self, owner, name):
        self.owner = owner
        self.name = name

        self.token = {
            "HYD": {},
            "DHYD": {},
            "THYD": {},
        }

        self.accounts_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.accounts_order_field_mapping = {
            "balance":       "balance",
            #"data":         "",
            "delegate":      "resigned",
            "id":            "address",
            #"key":          "",
            "name":          "username",
            "nonce":         "nonce",
            #"state":        "",
            #"state_reason": "",
            #"token":        "",
            #"ts":           "",
            "vote":          "vote",
        }

        self.accounts_state_reason_mapping = {
            #self.owner.KEY_A_STATE_REASON_None:                             "",
            self.owner.KEY_A_STATE_REASON_WalletIndexAlreadyRegisteredError: "The wallet index is already registered",
            self.owner.KEY_A_STATE_REASON_WalletIndexNotFoundError:          "The wallet index does not exist",
        }

        self.blocks_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.blocks_order_field_mapping = {
            #"confirmations":  "",
            #"data":           "",
            "forged_amount":   "totalAmount",
            "forged_fee":      "totalFee",
            "forged_reward":   "reward",
            #"forged_total":   "",
            #"generator_id":   "",
            #"generator_name": "",
            "height":          "height",
            #"id":             "",
            "transactions":    "numberOfTransactions",
            "ts":              "timestamp",
        }

        self.delegates_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.delegates_order_field_mapping = {
            #"data":          "",
            #"forged_amount": "",
            "forged_blocks":  "producedBlocks",
            "forged_fee":     "forgedFees",
            "forged_reward":  "forgedRewards",
            "forged_total":   "forgedTotal",
            "id":             "publicKey",
            "name":           "username",
            #"state":         "",
            "value":          "rank",
            "votes":          "votes",
            "votes_percent":  "votes",
        }

        self.delegates_state_mapping = {
            self.owner.DELEGATE_STATE_RESIGNED: "resigned",
            self.owner.DELEGATE_STATE_ACTIVE: "active",
            self.owner.DELEGATE_STATE_STANDBY: "standby",
        }

        self.infos_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.infos_order_field_mapping = {
        }

        self.transactions_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.transactions_order_field_mapping = {
            "amount":         "amount",
            #"block_id":      "",
            "comment":        "vendorField",
            #"confirmations": "",
            #"data":          "",
            #"dest":          "",
            #"direction":     "",
            "fee":            "fee",
            #"id":            "",
            #"index":         "",
            "nonce":          "nonce",
            #"source":        "",
            #"state":         "",
            #"state_reason":  "",
            "ts":             "timestamp",
            "type":           "type",
        }

        self.transactions_state_reason_mapping = {
            #self.owner.KEY_T_STATE_REASON_None:                                     "",
            self.owner.KEY_T_STATE_REASON_AlreadyVotedError:                         "Failed to apply transaction, because the sender wallet has already voted",
            self.owner.KEY_T_STATE_REASON_ColdWalletError:                           "Insufficient balance in database wallet. Wallet is not allowed to spend before funding is confirmed",
            self.owner.KEY_T_STATE_REASON_DeactivatedTransactionHandlerError:        "is deactivated",
            self.owner.KEY_T_STATE_REASON_HtlcLockExpiredError:                      "Failed to apply transaction, because the associated HTLC lock transaction expired",
            self.owner.KEY_T_STATE_REASON_HtlcLockNotExpiredError:                   "Failed to apply transaction, because the associated HTLC lock transaction did not expire yet",
            self.owner.KEY_T_STATE_REASON_HtlcLockTransactionNotFoundError:          "Failed to apply transaction, because the associated HTLC lock transaction could not be found",
            self.owner.KEY_T_STATE_REASON_HtlcSecretHashMismatchError:               "Failed to apply transaction, because the secret provided does not match the associated HTLC lock transaction secret",
            self.owner.KEY_T_STATE_REASON_InsufficientBalanceError:                  "Insufficient balance in the wallet",
            self.owner.KEY_T_STATE_REASON_InvalidMultiSignatureError:                "Failed to apply transaction, because the multi signature could not be verified",
            self.owner.KEY_T_STATE_REASON_InvalidMultiSignaturesError:               "Failed to apply transaction, because the multi signatures are invalid",
            self.owner.KEY_T_STATE_REASON_InvalidSecondSignatureError:               "Failed to apply transaction, because the second signature could not be verified",
            self.owner.KEY_T_STATE_REASON_InvalidTransactionTypeError:               "does not exist",
            self.owner.KEY_T_STATE_REASON_IpfsHashAlreadyExists:                     "Failed to apply transaction, because this IPFS hash is already registered on the blockchain",
            self.owner.KEY_T_STATE_REASON_LegacyMultiSignatureError:                 "Failed to apply transaction, because legacy multi signature is no longer supported",
            self.owner.KEY_T_STATE_REASON_LegacyMultiSignatureRegistrationError:     "Failed to apply transaction, because legacy multi signature registrations are no longer supported",
            self.owner.KEY_T_STATE_REASON_MissingMultiSignatureOnSenderError:        "Failed to apply transaction, because sender does not have a multi signature",
            self.owner.KEY_T_STATE_REASON_MultiSignatureAlreadyRegisteredError:      "Failed to apply transaction, because multi signature is already enabled",
            self.owner.KEY_T_STATE_REASON_MultiSignatureKeyCountMismatchError:       "Failed to apply transaction, because the number of provided keys does not match the number of signatures",
            self.owner.KEY_T_STATE_REASON_MultiSignatureMinimumKeysError:            "Failed to apply transaction, because too few keys were provided",
            self.owner.KEY_T_STATE_REASON_NotEnoughDelegatesError:                   "Failed to apply transaction, because not enough delegates to allow resignation",
            self.owner.KEY_T_STATE_REASON_NotImplementedError:                       "Feature is not available",
            self.owner.KEY_T_STATE_REASON_NotSupportedForMultiSignatureWalletError:  "Failed to apply transaction, because multi signature is enabled",
            self.owner.KEY_T_STATE_REASON_NoVoteError:                               "Failed to apply transaction, because the wallet has not voted",
            self.owner.KEY_T_STATE_REASON_SecondSignatureAlreadyRegisteredError:     "Failed to apply transaction, because second signature is already enabled",
            self.owner.KEY_T_STATE_REASON_SenderWalletMismatchError:                 "Failed to apply transaction, because the public key does not match the wallet",
            self.owner.KEY_T_STATE_REASON_UnexpectedNonceError:                      "a transaction with nonce",
            self.owner.KEY_T_STATE_REASON_UnexpectedSecondSignatureError:            "Failed to apply transaction, because wallet does not allow second signatures",
            self.owner.KEY_T_STATE_REASON_UnsupportedMultiSignatureTransactionError: "Failed to apply transaction, because the transaction does not support multi signatures",
            self.owner.KEY_T_STATE_REASON_UnvoteMismatchError:                       "Failed to apply transaction, because the wallet vote does not match",
            self.owner.KEY_T_STATE_REASON_VotedForNonDelegateError:                  "Failed to apply transaction, because only delegates can be voted",
            self.owner.KEY_T_STATE_REASON_VotedForResignedDelegateError:             "Failed to apply transaction, because it votes for a resigned delegate",
            self.owner.KEY_T_STATE_REASON_WalletAlreadyResignedError:                "Failed to apply transaction, because the wallet already resigned as delegate",
            self.owner.KEY_T_STATE_REASON_WalletIsAlreadyDelegateError:              "Failed to apply transaction, because the wallet already has a registered username",
            self.owner.KEY_T_STATE_REASON_WalletNotADelegateError:                   "Failed to apply transaction, because the wallet is not a delegate",
            self.owner.KEY_T_STATE_REASON_WalletNoUsernameError:                     "Failed to apply transaction, because the wallet has no registered username",
            self.owner.KEY_T_STATE_REASON_WalletUsernameAlreadyRegisteredError:      "Failed to apply transaction, because the username",
        }

        self.transactions_type_mapping = {
            self.owner.TRANSACTION_TYPE_TRANSFER:                 {"typeGroup": 1,"type": 0},
            #self.owner.TRANSACTION_TYPE_SWAP:                    {"typeGroup": 1,"type": 0},
            self.owner.TRANSACTION_TYPE_VOTE:                     {"typeGroup": 1,"type": 3},
            self.owner.TRANSACTION_TYPE_UNVOTE:                   {"typeGroup": 1,"type": 3},
            self.owner.TRANSACTION_TYPE_DELEGATE_REGISTRATION:    {"typeGroup": 1,"type": 2},
            self.owner.TRANSACTION_TYPE_DELEGATE_RESIGNATION:     {"typeGroup": 1,"type": 7},
            self.owner.TRANSACTION_TYPE_SECOND_SIGNATURE:         {"typeGroup": 1,"type": 1},
            self.owner.TRANSACTION_TYPE_MULTI_SIGNATURE:          {"typeGroup": 1,"type": 4},
            self.owner.TRANSACTION_TYPE_MULTI_PAYMENT:            {"typeGroup": 1,"type": 6},
            self.owner.TRANSACTION_TYPE_IPFS:                     {"typeGroup": 1,"type": 5},
            self.owner.TRANSACTION_TYPE_TIMELOCK_TRANSFER:        {"typeGroup": 1,"type": 8},
            self.owner.TRANSACTION_TYPE_TIMELOCK_CLAIM:           {"typeGroup": 1,"type": 9},
            self.owner.TRANSACTION_TYPE_TIMELOCK_REFUND:          {"typeGroup": 1,"type": 10},
            self.owner.TRANSACTION_TYPE_BUSINESS_REGISTRATION:    {"typeGroup": 2,"type": 0},
            self.owner.TRANSACTION_TYPE_BUSINESS_RESIGNATION:     {"typeGroup": 2,"type": 1},
            self.owner.TRANSACTION_TYPE_BUSINESS_UPDATE:          {"typeGroup": 2,"type": 2},
            self.owner.TRANSACTION_TYPE_BRIDGECHAIN_REGISTRATION: {"typeGroup": 2,"type": 3},
            self.owner.TRANSACTION_TYPE_BRIDGECHAIN_RESIGNATION:  {"typeGroup": 2,"type": 4},
            self.owner.TRANSACTION_TYPE_BRIDGECHAIN_UPDATE:       {"typeGroup": 2,"type": 5},
            self.owner.TRANSACTION_TYPE_SSI_TRANSACTION:          {"typeGroup": 4242,"type": 1},
            self.owner.TRANSACTION_TYPE_DNS_TRANSACTION:          {"typeGroup": 4242,"type": 2},
        }

        self.iop = sdk.IopPython()

        self.config = self.owner.config_load(file=self.name+".cfg", default=self.DEFAULT_CONFIG)
        self.config_changed = False

        threading.Thread(target=self.jobs, daemon=True).start()


    #################################################
    # Accounts                                      #
    #################################################


    def accounts_add(self, token, data):
        account = int(self.config[token]["account"])
        idx = int(self.config[token]["idx"])
        network = self.config[token]["network"]
        password = self.config[token]["password"]

        if "account" in data:
            account = int(data["account"])
        if "idx" in data:
            idx = int(data["idx"])
        if "network" in data:
            network = data["network"].strip()
        if "password" in data:
            password = data["password"].strip()
        if "phrase" in data:
            phrase = data["phrase"].strip()

        if not password:
            password = HMAC.new(phrase.encode("utf8")).hexdigest()

        morpheus = self.iop.get_morpheus_vault(phrase, password)
        vault = self.iop.get_hyd_vault(phrase, password, network, account)
        account_id = self.iop.get_wallet_address(vault, account, idx, network)
        did = self.iop.generate_did_by_morpheus(morpheus, password, idx) if idx == 0 else ""

        result = {
            "account_id":   account_id,
            "data": {
                "morpheus": morpheus,
                "vault":    vault
            },
            "metadata": {
                "did":      did
            },
            "state":        self.owner.ACCOUNT_STATE_SUCCESSFULL
        }

        return result


    def accounts_count(self, token, filter, search):
        return 0


    def accounts_get(self, token, account_id):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/wallets/{account_id}"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            res = data["data"]
            result = {
                "balance":  int(res["balance"]),
                "delegate": res["username"] if "username" in res and "isDelegate" in res and "isResigned" in res and res["isDelegate"] == True and res["isResigned"] == False else "",
                "name":     "",
                "nonce":    int(res["nonce"]),
                "vote":     res["attributes"]["vote"] if "attributes" in res and "vote" in res["attributes"] else ""
            }

        else:
            result = {
                "balance":  0,
                "delegate": "",
                "name":     "",
                "nonce":    0,
                "vote":     ""
            }

        return result


    def accounts_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        data_filter = {}
        if filter:
            for filter_key, filter_value in filter.items(): 
                if filter_key == "balance":
                    data_filter["balance"] = {}
                    if filter_value[0] != None:
                        data_filter["balance"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["balance"]["to"] = filter_value[1]
                elif filter_key == "id":
                    data_filter["address"] = filter_value
                elif filter_key == "name":
                    data_filter["username"] = filter_value
                elif filter_key == "vote":
                    data_filter["vote"] = filter_value
        if search:
            data_filter["address"] = search

        url_order = ""
        if order and order[0] in self.accounts_order_field_mapping and order[1] in self.accounts_order_direction_mapping:
            url_order = f"&orderBy={self.accounts_order_field_mapping[order[0]]}:{self.accounts_order_direction_mapping[order[1]]}"

        server_api_limit = int(self.config["main"]["server_api_limit"])
        if limit > server_api_limit:
            limit = server_api_limit

        if len(data_filter) > 0:
            url = f"http://{server}:4703/api/v2/wallets/search?limit={limit}&offset={limit_start}{url_order}"
        else:
            url = f"http://{server}:4703/api/v2/wallets?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        if len(data_filter) > 0:
            response = requests.post(url, timeout=timeout, json=data_filter)
        else:
            response = requests.get(url, timeout=timeout)

        if response.status_code != 200 and search:
            if "address" in data_filter: del data_filter["address"]
            if "publicKey" in data_filter: del data_filter["publicKey"]
            if "username" in data_filter: del data_filter["username"]
            data_filter["publicKey"] = search
            response = requests.post(url, timeout=timeout, json=data_filter)
            if response.status_code != 200:
                if "address" in data_filter: del data_filter["address"]
                if "publicKey" in data_filter: del data_filter["publicKey"]
                if "username" in data_filter: del data_filter["username"]
                data_filter["username"] = search
                response = requests.post(url, timeout=timeout, json=data_filter)
                if response.status_code != 200:
                    return (count, result)
        elif response.status_code != 200:
            return (count, result)

        data = response.json()
        count = data["meta"]["totalCount"] if "meta" in data else 1
        if isinstance(data["data"], dict):
            data["data"] = [data["data"]]
        for res in data["data"]:
            result[res["address"]] = {
                "balance":  int(res["balance"]),
                "delegate": "1" if "isDelegate" in res and "isResigned" in res and res["isDelegate"] == True and res["isResigned"] == False else "",
                "key":      res["publicKey"] if "publicKey" in res else "",
                "name":     res["username"] if "username" in res else "",
                "nonce":    int(res["nonce"]),
                "vote":     res["attributes"]["vote"] if "attributes" in res and "vote" in res["attributes"] else ""
            }

        return (count, result)


    #################################################
    # API                                           #
    #################################################


    def api_delete(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_get(self, token, url, data, json, headers, cookies, auth, timeout):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/"+url
        if not timeout:
            timeout = int(self.config["main"]["server_timeout"])
        response = requests.get(url, params=json if json else data, headers=headers, cookies=cookies, auth=auth, timeout=timeout)
        if response.status_code == 200:
            result = {
                "status_code": response.status_code,
                "data":        response.json()
            }
        else:
            result = {
                "status_code": response.status_code,
                "data":        None
            }
        return result


    def api_patch(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    def api_post(self, token, url, data, json, headers, cookies, auth, timeout):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/"+url
        if not timeout:
            timeout = int(self.config["main"]["server_timeout"])
        response = requests.post(url, data=data, json=json, headers=headers, cookies=cookies, auth=auth, timeout=timeout)
        if response.status_code == 200:
            result = {
                "status_code": response.status_code,
                "data":        response.json()
            }
        else:
            result = {
                "status_code": response.status_code,
                "data":        None
            }
        return result


    def api_put(self, token, url, data, json, headers, cookies, auth, timeout):
        raise ValueError("Not implemented")


    #################################################
    # Blocks                                        #
    #################################################


    def blocks_count(self, token, filter, search):
        return 0


    def blocks_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        url_filter = ""
        data_filter = {}
        if filter:
            for filter_key, filter_value in filter.items(): 
                if filter_key == "forged_amount":
                    data_filter["totalAmount"] = {}
                    if filter_value[0] != None:
                        data_filter["totalAmount"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["totalAmount"]["to"] = filter_value[1]
                elif filter_key == "forged_fee":
                    data_filter["totalFee"] = {}
                    if filter_value[0] != None:
                        data_filter["totalFee"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["totalFee"]["to"] = filter_value[1]
                elif filter_key == "generator_id":
                    data_filter["generatorPublicKey"] = filter_value
                elif filter_key == "id":
                    data_filter["id"] = filter_value
                elif filter_key == "ts":
                    data_filter["timestamp"] = {}
                    if filter_value[0] != None:
                        data_filter["timestamp"]["from"] = filter_value[0]-1567324800
                    if filter_value[1] != None:
                        data_filter["timestamp"]["to"] = filter_value[1]-1567324800

        url_order = ""
        if order and order[0] in self.blocks_order_field_mapping and order[1] in self.blocks_order_direction_mapping:
            url_order = f"&orderBy={self.blocks_order_field_mapping[order[0]]}:{self.blocks_order_direction_mapping[order[1]]}"
            if len(data_filter) > 0:
                data_filter["orderBy"] = f"{self.blocks_order_field_mapping[order[0]]}:{self.blocks_order_direction_mapping[order[1]]}"

        server_api_limit = int(self.config["main"]["server_api_limit"])
        if limit > server_api_limit:
            limit = server_api_limit

        if len(data_filter) > 0:
            url = f"http://{server}:4703/api/v2/blocks/search?limit={limit}&offset={limit_start}{url_filter}"
            search = None
        elif search:
            url = f"http://{server}:4703/api/v2/delegates/{search}/blocks?limit={limit}&offset={limit_start}{url_order}{url_filter}"
        else:
            url = f"http://{server}:4703/api/v2/blocks?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        if len(data_filter) > 0:
            response = requests.post(url, timeout=timeout, json=data_filter)
        else:
            response = requests.get(url, timeout=timeout)

        if response.status_code != 200 and search:
            url = f"http://{server}:4703/api/v2/blocks/{search}"
            response = requests.get(url, timeout=timeout)
            if response.status_code != 200:
                return (count, result)
        elif response.status_code != 200:
            return (count, result)

        data = response.json()
        count = data["meta"]["totalCount"] if "meta" in data else 1
        if isinstance(data["data"], dict):
            data["data"] = [data["data"]]
        for res in data["data"]:
            result[res["id"]] = {
                "confirmations":  int(res["confirmations"]),
                #"data":          "",
                "forged_amount":  int(res["forged"]["amount"]),
                "forged_fee":     int(res["forged"]["fee"]),
                "forged_reward":  int(res["forged"]["reward"]),
                "forged_total":   int(res["forged"]["total"]),
                "generator_id":   res["generator"]["address"],
                "generator_name": res["generator"]["username"] if "username" in res["generator"] else "",
                "height":         int(res["height"]),
                "transactions":   int(res["transactions"]),
                "ts":             int(res["timestamp"]["unix"])
            }

        return (count, result)


    #################################################
    # Connection                                    #
    #################################################


    def connection_response_start(self, token):
        self.server_select(token)


    def connection_response_stop(self, token):
        pass


    #################################################
    # Delegates                                     #
    #################################################


    def delegates_count(self, token, filter, search):
        return 0


    def delegates_get(self, token):
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/delegates?page=1&limit=53&orderBy=rank:asc"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            return result

        data = response.json()
        for res in data["data"]:
            if res["isResigned"]:
                state = "resigned"
            elif "rank" in res and res["rank"] < 54:
                state = "active"
            else:
                state = "standby"
            for key, value in self.delegates_state_mapping.items():
                if value == state:
                    state = key
                    break
            result[res["publicKey"]] = {
                "name":  res["username"],
                "state": state,
                "value": res["rank"]
            }

        return result


    def delegates_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        data_filter = {}
        if filter:
            for filter_key, filter_value in filter.items():
                if filter_key == "forged_blocks":
                    data_filter["producedBlocks"] = {}
                    if filter_value[0] != None:
                        data_filter["producedBlocks"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["producedBlocks"]["to"] = filter_value[1]
                if filter_key == "forged_fee":
                    data_filter["forgedFees"] = {}
                    if filter_value[0] != None:
                        data_filter["forgedFees"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["forgedFees"]["to"] = filter_value[1]
                if filter_key == "forged_reward":
                    data_filter["forgedRewards"] = {}
                    if filter_value[0] != None:
                        data_filter["forgedRewards"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["forgedRewards"]["to"] = filter_value[1]
                if filter_key == "forged_total":
                    data_filter["forgedTotal"] = {}
                    if filter_value[0] != None:
                        data_filter["forgedTotal"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["forgedTotal"]["to"] = filter_value[1]
                elif filter_key == "id":
                    data_filter["publicKey"] = filter_value
                elif filter_key == "name":
                    data_filter["username"] = filter_value
                elif filter_key == "votes":
                    data_filter["voteBalance"] = {}
                    if filter_value[0] != None:
                        data_filter["voteBalance"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["voteBalance"]["to"] = filter_value[1]
                elif filter_key == "votes_percent":
                    data_filter["voteBalance"] = {}
                    if filter_value[0] != None:
                        data_filter["voteBalance"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["voteBalance"]["to"] = filter_value[1]
        if search:
            data_filter["address"] = search

        url_order = ""
        if order and order[0] in self.delegates_order_field_mapping and order[1] in self.delegates_order_direction_mapping:
            url_order = f"&orderBy={self.delegates_order_field_mapping[order[0]]}:{self.delegates_order_direction_mapping[order[1]]}"

        server_api_limit = int(self.config["main"]["server_api_limit"])
        if limit > server_api_limit:
            limit = server_api_limit

        if len(data_filter) > 0:
            url = f"http://{server}:4703/api/v2/delegates/search?limit={limit}&offset={limit_start}{url_order}"
        else:
            url = f"http://{server}:4703/api/v2/delegates?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        if len(data_filter) > 0:
            response = requests.post(url, timeout=timeout, json=data_filter)
        else:
            response = requests.get(url, timeout=timeout)

        if response.status_code != 200 and search:
            if "address" in data_filter: del data_filter["address"]
            if "publicKey" in data_filter: del data_filter["publicKey"]
            if "username" in data_filter: del data_filter["username"]
            data_filter["publicKey"] = search
            response = requests.post(url, timeout=timeout, json=data_filter)
            if response.status_code != 200:
                if "address" in data_filter: del data_filter["address"]
                if "publicKey" in data_filter: del data_filter["publicKey"]
                if "username" in data_filter: del data_filter["username"]
                data_filter["username"] = search
                response = requests.post(url, timeout=timeout, json=data_filter)
                if response.status_code != 200:
                    return (count, result)
        elif response.status_code != 200:
            return (count, result)

        data = response.json()
        count = data["meta"]["totalCount"] if "meta" in data else 1
        if isinstance(data["data"], dict):
            data["data"] = [data["data"]]
        for res in data["data"]:
            if res["isResigned"]:
                state = "resigned"
            elif "rank" in res and res["rank"] < 54:
                state = "active"
            else:
                state = "standby"
            for key, value in self.delegates_state_mapping.items():
                if value == state:
                    state = key
                    break
            result[res["publicKey"]] = {
                "block_id":      res["blocks"]["last"]["id"] if "blocks" in res and "last" in res["blocks"] else "",
                "block_ts":      int(res["blocks"]["last"]["timestamp"]["unix"]) if "blocks" in res and "last" in res["blocks"] else 0,
                "forged_blocks": int(res["blocks"]["produced"]) if "blocks" in res else 0,
                "forged_total":  int(res["forged"]["total"]) if "forged" in res else 0,
                "name":          res["username"],
                "state":         state,
                "value":         int(res["rank"]) if "rank" in res else 0,
                "votes":         int(res["votes"]) if "votes" in res else 0,
                "votes_percent": float(res["production"]["approval"]) if "production" in res else 0
            }

        return (count, result)


    #################################################
    # Infos                                         #
    #################################################


    def infos_count(self, token, filter, search):
        return 0


    def infos_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        url = f"http://{server}:4703/api/v2/blockchain"

        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            return (count, result)

        data = response.json()
        count = 1
        res = data["data"]
        result[token] = {
            "block":        {"height": int(res["block"]["height"]), "id": res["block"]["id"]},
            #"data":        {},
            "supply":       int(res["supply"]),
            #"transaction": {},
        }

        return (count, result)


    #################################################
    # Transactions                                  #
    #################################################


    def transactions_add(self, token, account_id, account_data, transaction_data):
        if "data" in transaction_data:
            data = json.loads(transaction_data["data"])
        else:
            account = int(self.config[token]["account"])
            idx = int(self.config[token]["idx"])
            network = self.config[token]["network"]
            password = self.config[token]["password"]

            if "account" in account_data:
                account = int(account_data["account"])
            if "idx" in account_data:
                idx = int(account_data["idx"])
            if "network" in account_data:
                network = account_data["network"].strip()
            if "password" in account_data:
                password = account_data["password"].strip()
            if "phrase" in account_data:
                phrase = account_data["phrase"].strip()

            if not password:
                password = HMAC.new(phrase.encode("utf8")).hexdigest()

            if transaction_data["type"] == self.owner.TRANSACTION_TYPE_TRANSFER:
                data = self.iop.sign_transaction(
                    self.iop.get_hyd_vault(phrase, password, network, account),
                    transaction_data["dest"],
                    int(transaction_data["amount"]),
                    transaction_data["nonce"] if "nonce" in transaction_data else self.get_nonce(token, account_id),
                    password,
                    account,
                    idx,
                    network,
                    transaction_data["comment"] if "comment" in transaction_data else None,
                    transaction_data["fee"] if "fee" in transaction_data else None
                )
                data = json.loads(data)

            elif transaction_data["type"] == self.owner.TRANSACTION_TYPE_VOTE:
                data = self.iop.vote(
                    self.iop.get_hyd_vault(phrase, password, network, account),
                    transaction_data["nonce"] if "nonce" in transaction_data else self.get_nonce(token, account_id),
                    password,
                    account,
                    idx,
                    network,
                    transaction_data["dest"]
                )
                data = json.loads(data)

            elif transaction_data["type"] == self.owner.TRANSACTION_TYPE_UNVOTE:
                data = self.iop.unvote(
                    self.iop.get_hyd_vault(phrase, password, network, account),
                    transaction_data["nonce"] if "nonce" in transaction_data else self.get_nonce(token, account_id),
                    password,
                    account,
                    idx,
                    network,
                    transaction_data["dest"]
                )
                data = json.loads(data)

            elif transaction_data["type"] == self.owner.TRANSACTION_TYPE_DELEGATE_REGISTRATION:
                data = self.iop.register_delegate(
                    self.iop.get_hyd_vault(phrase, password, network, account),
                    transaction_data["nonce"] if "nonce" in transaction_data else self.get_nonce(token, account_id),
                    password,
                    account,
                    idx,
                    network,
                    transaction_data["comment"] if "comment" in transaction_data else None
                )
                data = json.loads(data)

            elif transaction_data["type"] == self.owner.TRANSACTION_TYPE_DELEGATE_RESIGNATION:
                raise ValueError("Not implemented")

            else:
                raise ValueError("Not implemented")

        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/transactions"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.post(url, timeout=timeout, json=data)

        #print(data)
        #print(response.json())

        if response.status_code == 200:
            data = response.json()
            if len(data["data"]["accept"]) > 0:
                result = {
                    "transaction_id": data["data"]["accept"][0]
                }
                return result
            elif len(data["errors"]) > 0:
                error_key = next(iter(data["errors"]))
                error_message = data["errors"][error_key][0]["message"]
                for key, value in self.transactions_state_reason_mapping.items():
                    if value in error_message:
                        result = {
                            "state": self.owner.TRANSACTION_STATE_FAILED,
                            "state_reason": key
                        }
                        return result

        raise ValueError(response.text)


    def transactions_count(self, token, filter, search):
        return 0


    def transactions_get(self, token, account_id, ts):
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        data_filter = {}
        data_filter["addresses"] = [account_id]
        data_filter["orderBy"] = f"{self.transactions_order_field_mapping['ts']}:{self.transactions_order_direction_mapping['asc']}"
        if ts:
            data_filter["timestamp"] = {"from": ts-1567324800}

        url = f"http://{server}:4703/api/v2/transactions/search"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.post(url, timeout=timeout, json=data_filter)

        if response.status_code != 200:
            return result

        data = response.json()
        for res in data["data"]:
            if res["timestamp"]["unix"] <= ts:
                continue

            result[res["id"]] = {
                "amount":        int(res["amount"]),
                "comment":       res["vendorField"] if "vendorField" in res else "",
                "confirmations": int(res["confirmations"]),
                "dest":          res["recipient"],
                "fee":           int(res["fee"]),
                "source":        res["sender"],
                "ts":            int(res["timestamp"]["unix"])
            }

            if "typeGroup" in res and "type" in res:
                for key, value in self.transactions_type_mapping.items():
                    if value["typeGroup"] == res["typeGroup"] and value["type"] == res["type"]:
                        result[res["id"]]["type"] = key
                        break

            if "asset" in res and "votes" in res["asset"] and len(res["asset"]["votes"]) > 0:
                vote = res["asset"]["votes"][0]
                if vote.startswith('+'):
                    result[res["id"]]["type"] = self.owner.TRANSACTION_TYPE_VOTE
                else:
                    result[res["id"]]["type"] = self.owner.TRANSACTION_TYPE_UNVOTE
                vote = vote[1:]
                result[res["id"]]["dest"] = self.get_account_id(token=token, account_id=vote)

        return result


    def transactions_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        data_filter = {}
        if filter:
            for filter_key, filter_value in filter.items(): 
                if filter_key == "amount":
                    data_filter["amount"] = {}
                    if filter_value[0] != None:
                        data_filter["amount"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["amount"]["to"] = filter_value[1]
                elif filter_key == "comment":
                    data_filter["vendorField"] = filter_value
                elif filter_key == "direction":
                    if search:
                        if filter_value == 0x00:
                            data_filter["recipientId"] = search
                        else:
                            data_filter["senderId"] = search
                        search = None
                elif filter_key == "fee":
                    data_filter["fee"] = {}
                    if filter_value[0] != None:
                        data_filter["fee"]["from"] = filter_value[0]
                    if filter_value[1] != None:
                        data_filter["fee"]["to"] = filter_value[1]
                elif filter_key == "id":
                    data_filter["id"] = filter_value
                elif filter_key == "nonce":
                    data_filter["nonce"] = filter_value
                elif filter_key == "type":
                    if filter_value in self.transactions_type_mapping:
                        data_filter["type"] = self.transactions_type_mapping[filter_value]["type"]
                        data_filter["typeGroup"] = self.transactions_type_mapping[filter_value]["typeGroup"]
                elif filter_key == "ts":
                    data_filter["timestamp"] = {}
                    if filter_value[0] != None:
                        data_filter["timestamp"]["from"] = filter_value[0]-1567324800
                    if filter_value[1] != None:
                        data_filter["timestamp"]["to"] = filter_value[1]-1567324800
        if search:
            data_filter["addresses"] = [search]

        url_order = ""
        if order and order[0] in self.transactions_order_field_mapping and order[1] in self.transactions_order_direction_mapping:
            url_order = f"&orderBy={self.transactions_order_field_mapping[order[0]]}:{self.transactions_order_direction_mapping[order[1]]}"
            if len(data_filter) > 0:
                data_filter["orderBy"] = f"{self.transactions_order_field_mapping[order[0]]}:{self.transactions_order_direction_mapping[order[1]]}"

        server_api_limit = int(self.config["main"]["server_api_limit"])
        if limit > server_api_limit:
            limit = server_api_limit

        if len(data_filter) > 0:
            url = f"http://{server}:4703/api/v2/transactions/search?limit={limit}&offset={limit_start}"
        else:
            url = f"http://{server}:4703/api/v2/transactions?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        if len(data_filter) > 0:
            response = requests.post(url, timeout=timeout, json=data_filter)
        else:
            response = requests.get(url, timeout=timeout)

        if response.status_code != 200 and search:
            if "addresses" in data_filter: del data_filter["addresses"]
            if "id" in data_filter: del data_filter["id"]
            if "senderPublicKey" in data_filter: del data_filter["senderPublicKey"]
            data_filter["id"] = search
            response = requests.post(url, timeout=timeout, json=data_filter)
            if response.status_code != 200:
                if "addresses" in data_filter: del data_filter["addresses"]
                if "id" in data_filter: del data_filter["id"]
                if "senderPublicKey" in data_filter: del data_filter["senderPublicKey"]
                data_filter["senderPublicKey"] = search
                response = requests.post(url, timeout=timeout, json=data_filter)
                if response.status_code != 200:
                    return (count, result)
        elif response.status_code != 200:
            return (count, result)

        data = response.json()
        count = data["meta"]["totalCount"] if "meta" in data else 1
        if isinstance(data["data"], dict):
            data["data"] = [data["data"]]
        for res in data["data"]:
            result[res["id"]] = {
                "amount":        int(res["amount"]),
                "block_id":      res["blockId"],
                "comment":       res["vendorField"] if "vendorField" in res else "",
                "confirmations": int(res["confirmations"]),
                "dest":          res["recipient"],
                "fee":           int(res["fee"]),
                "nonce":         res["nonce"],
                "source":        res["sender"],
                "ts":            int(res["timestamp"]["unix"])
            }

            if "typeGroup" in res and "type" in res:
                for key, value in self.transactions_type_mapping.items():
                    if value["typeGroup"] == res["typeGroup"] and value["type"] == res["type"]:
                        result[res["id"]]["type"] = key
                        break

            if "asset" in res and "votes" in res["asset"] and len(res["asset"]["votes"]) > 0:
                vote = res["asset"]["votes"][0]
                if vote.startswith('+'):
                    result[res["id"]]["type"] = self.owner.TRANSACTION_TYPE_VOTE
                else:
                    result[res["id"]]["type"] = self.owner.TRANSACTION_TYPE_UNVOTE
                vote = vote[1:]
                result[res["id"]]["dest"] = self.get_account_id(token=token, account_id=vote)

        return (count, result)


    #################################################
    # Helpers - Functions                           #
    #################################################


    def get_account_id(self, token, account_id):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/wallets/{account_id}"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            return data["data"]["address"]
        else:
            return account_id


    def get_nonce(self, token, account_id):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/wallets/{account_id}"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            return int(data["data"]["nonce"])
        else:
            return 0


    #################################################
    # Helpers - Jobs                                #
    #################################################


    def jobs(self):
        server_discovery = 0
        server_check = 0

        while True:
            try:
                time.sleep(10)

                now = time.time()

                if not self.config:
                    self.config = self.owner.config_load(file=self.name+".cfg", default=self.DEFAULT_CONFIG)
 
                if now-server_discovery > int(self.config["main"]["server_discovery_interval"])*60:
                    server_discovery = now
                    for token in self.token:
                        self.server_select(token)
                        self.server_discovery(token)

                if now-server_check > int(self.config["main"]["server_check_interval"])*60:
                    server_check = now
                    for token in self.token:
                        self.server_check(token)

                if self.config_changed:
                    self.config_changed = False
                    self.owner.config_save(file=self.name+".cfg", config=self.config)

            except Exception as e:
                self.owner.log_exception(e, "HYD - Jobs")


    #################################################
    # Helpers - Server                              #
    #################################################


    def server(self, token):
        if not self.config.has_section(token):
            return None

        if not self.config.has_option(token, "server"):
            return None

        server = self.config[token]["server"]

        if not self.config.has_section(token+"_server"):
            return None

        if not self.config.has_option(token+"_server", server):
            return None
        
        if self.config[token+"_server"][server] == "False":
            return None

        return server


    def server_check(self, token):
        if not self.config.has_section(token+"_server"):
            return

        for server, online_old in self.config.items(token+"_server"):
            online_new = "True" if self.server_ping(server) else "False"
            if online_new != online_old:
                self.config.set(token+"_server", server, online_new)
                self.config_changed = True


    def server_discovery(self, token):
        try:
            server = self.server(token)
            if not server:
                raise ValueError("No server")
            url = f"http://{server}:4703/api/v2/peers"
            timeout = int(self.config["main"]["server_timeout"])
            response = requests.get(url, timeout=timeout)

            if response.status_code == 200:
                data = response.json()
                if len(data["data"]) > 0:
                    for res in data["data"]:
                        self.config.set(token+"_server", res["ip"], "True")
                    self.config_changed = True
                return True
        except Exception as e:
            pass
        return False


    def server_ping(self, server):
        try:
            url = f"http://{server}:4703"
            timeout = int(self.config["main"]["server_timeout"])
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return True
        except Exception as e:
            pass
        return False


    def server_select(self, token):
        if not self.config.has_section(token):
            return

        if not self.config.has_option(token, "server"):
            return

        if not self.config.has_section(token+"_server"):
            return

        if self.server_ping(self.config[token]["server"]):
            self.config.set(token+"_server", self.config[token]["server"], "True")
            return

        for server, online in self.config.items(token+"_server"):
            if online == "False":
                continue
            if self.server_ping(server):
                self.config[token]["server"] = server
                return
