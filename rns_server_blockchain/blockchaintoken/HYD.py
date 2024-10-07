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


    def __init__(self, owner):
        self.owner = owner

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
            "balance":      "balance",
            #"data":         "",
            "delegate":     "resigned",
            "id":           "address",
            "name":         "username",
            "nonce":        "nonce",
            #"state":        "",
            #"state_reason": "",
            #"token":        "",
            #"ts":           "",
            "vote":         "vote",
        }

        self.blocks_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.blocks_order_field_mapping = {
            #"confirmations":  "",
            #"data":           "",
            "forged_amount":  "totalAmount",
            "forged_fee":     "totalFee",
            #"forged_reward":  "",
            #"forged_total":   "",
            #"generator_id":   "",
            #"generator_name": "",
            "height":         "height",
            #"id":             "",
            "transactions":   "numberOfTransactions",
            "ts":             "timestamp",
        }

        self.delegates_order_direction_mapping = {
            "asc":  "asc",
            "desc": "desc",
        }

        self.delegates_order_field_mapping = {
            #"data":  "",
            "id":    "publicKey",
            "name":  "username",
            #"state": "",
            "value": "rank",
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
            "amount":        "amount",
            "comment":       "vendorField",
            #"confirmations": "",
            #"data":          "",
            #"dest":          "",
            "fee":           "fee",
            #"id":            "",
            #"index":         "",
            #"source":        "",
            #"state":         "",
            #"state_reason":  "",
            "ts":            "timestamp",
            "type":          "type",
        }

        self.transactions_type_mapping = {
            0: None,
            1: self.owner.TRANSACTION_TYPE_SECOND_SIGNATURE,
            2: self.owner.TRANSACTION_TYPE_DELEGATE_REGISTRATION,
            3: self.owner.TRANSACTION_TYPE_VOTE,
            4: self.owner.TRANSACTION_TYPE_MULTI_SIGNATURE,
            5: self.owner.TRANSACTION_TYPE_IPFS,
            6: self.owner.TRANSACTION_TYPE_MULTI_PAYMENT,
            7: self.owner.TRANSACTION_TYPE_DELEGATE_RESIGNATION,
            8: self.owner.TRANSACTION_TYPE_TIMELOCK_TRANSFER,
            9: self.owner.TRANSACTION_TYPE_TIMELOCK_CLAIM,
            10: self.owner.TRANSACTION_TYPE_TIMELOCK_REFUND,
        }

        self.iop = sdk.IopPython()

        self.config = self.owner.config_load(file="HYD.cfg", default=BlockchainTokenHYD.DEFAULT_CONFIG)
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

        result = {
            "account_id":   account_id,
            "data": {
                "morpheus": morpheus,
                "vault":    vault
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
                "nonce":    int(res["nonce"]),
                "name":     "",
                "delegate": "",
                "vote":     res["attributes"]["vote"] if "attributes" in res and "vote" in res["attributes"] else ""
            }

        else:
            result = {
                "balance":  0,
                "nonce":    0,
                "name":     "",
                "delegate": "",
                "vote":     ""
            }

        return result


    def accounts_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        if order and order[0] in self.accounts_order_field_mapping and order[1] in self.accounts_order_direction_mapping:
            url_order = f"&orderBy={self.accounts_order_field_mapping[order[0]]}:{self.accounts_order_direction_mapping[order[1]]}"
        else:
            url_order = ""

        if search:
            url = f"http://{server}:4703/api/v2/wallets/{search}?limit={limit}&offset={limit_start}"
        else:
            url = f"http://{server}:4703/api/v2/wallets?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            if search:
                count = 1
                res = data["data"]
                result[res["address"]] = {
                    "balance":  int(res["balance"]),
                    "nonce":    int(res["nonce"]),
                    "name":     res["username"] if "username" in res else "",
                    "delegate": "1" if "isDelegate" in res and "isResigned" in res and res["isDelegate"] == True and res["isResigned"] == False else "",
                    "vote":     res["attributes"]["vote"] if "attributes" in res and "vote" in res["attributes"] else ""
                }
            else:
                count = data["meta"]["totalCount"]
                for res in data["data"]:
                    result[res["address"]] = {
                        "balance":  int(res["balance"]),
                        "nonce":    int(res["nonce"]),
                        "name":     res["username"] if "username" in res else "",
                        "delegate": "1" if "isDelegate" in res and "isResigned" in res and res["isDelegate"] == True and res["isResigned"] == False else "",
                        "vote":     res["attributes"]["vote"] if "attributes" in res and "vote" in res["attributes"] else ""
                    }

        return (count, result)


    #################################################
    # API                                           #
    #################################################


    def api_delete(self, token, url, data, json, headers, cookies, auth):
        raise ValueError("Not implemented")


    def api_get(self, token, url, data, json, headers, cookies, auth):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/"+url
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


    def api_patch(self, token, url, data, json, headers, cookies, auth):
        raise ValueError("Not implemented")


    def api_post(self, token, url, data, json, headers, cookies, auth):
        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/"+url
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


    def api_put(self, token, url, data, json, headers, cookies, auth):
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

        if order and order[0] in self.blocks_order_field_mapping and order[1] in self.blocks_order_direction_mapping:
            url_order = f"&orderBy={self.blocks_order_field_mapping[order[0]]}:{self.blocks_order_direction_mapping[order[1]]}"
        else:
            url_order = ""

        if search:
            url = f"http://{server}:4703/api/v2/blocks/{search}"
        else:
            url = f"http://{server}:4703/api/v2/blocks?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            if search:
                count = 1
                res = data["data"]
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
            else:
                count = data["meta"]["totalCount"]
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

        if response.status_code == 200:
            data = response.json()
            for res in data["data"]:
                result[res["publicKey"]] = {
                    "name":  res["username"],
                    "value": res["rank"],
                    "state": 0x00 if res["isResigned"] else 0x01
                }

        return result


    def delegates_list(self, token, filter, search, order, limit, limit_start):
        count = 0
        result = {}

        server = self.server(token)
        if not server:
            raise ValueError("No server")

        if order and order[0] in self.delegates_order_field_mapping and order[1] in self.delegates_order_direction_mapping:
            url_order = f"&orderBy={self.delegates_order_field_mapping[order[0]]}:{self.delegates_order_direction_mapping[order[1]]}"
        else:
            url_order = ""

        if search:
            url = f"http://{server}:4703/api/v2/delegates/{search}?limit={limit}&offset={limit_start}"
        else:
            url = f"http://{server}:4703/api/v2/delegates?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            if search:
                count = 1
                res = data["data"]
                result[res["publicKey"]] = {
                    "name":  res["username"],
                    "value": res["rank"] if "rank" in res else 0,
                    "state": 0x00 if res["isResigned"] else 0x01
                }
            else:
                count = data["meta"]["totalCount"]
                for res in data["data"]:
                    result[res["publicKey"]] = {
                        "name":  res["username"],
                        "value": res["rank"] if "rank" in res else 0,
                        "state": 0x00 if res["isResigned"] else 0x01
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

        if response.status_code == 200:
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
            response_transaction = json.loads(transaction_data["data"])
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

            response_transaction = self.iop.sign_transaction(
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
            response_transaction = json.loads(response_transaction)

        server = self.server(token)
        if not server:
            raise ValueError("No server")
        url = f"http://{server}:4703/api/v2/transactions"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.post(url, timeout=timeout, json=response_transaction)

        #print(response_transaction)
        #print(response.json())

        if response.status_code == 200:
            data = response.json()
            if len(data["data"]["accept"]) > 0:
                result = {
                    "transaction_id": data["data"]["accept"][0]
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
        url = f"http://{server}:4703/api/v2/wallets/{account_id}/transactions"
        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            for res in data["data"]:
                if res["timestamp"]["unix"] <= ts:
                    continue
                result[res["id"]] = {
                    "source":        res["sender"],
                    "dest":          res["recipient"],
                    "amount":        int(res["amount"]),
                    "comment":       res["vendorField"] if "vendorField" in res else "",
                    "confirmations": int(res["confirmations"]),
                    "fee":           int(res["fee"]),
                    "ts":            int(res["timestamp"]["unix"])
                }
                if "type" in res and res["type"] in self.transactions_type_mapping:
                    result[res["id"]]["type"] = self.transactions_type_mapping[res["type"]]
                
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

        if order and order[0] in self.transactions_order_field_mapping and order[1] in self.transactions_order_direction_mapping:
            url_order = f"&orderBy={self.transactions_order_field_mapping[order[0]]}:{self.transactions_order_direction_mapping[order[1]]}"
        else:
            url_order = ""

        if search:
            url = f"http://{server}:4703/api/v2/wallets/{search}/transactions?limit={limit}&offset={limit_start}{url_order}"
        else:
            url = f"http://{server}:4703/api/v2/transactions?limit={limit}&offset={limit_start}{url_order}"

        timeout = int(self.config["main"]["server_timeout"])

        response = requests.get(url, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            count = data["meta"]["totalCount"]
            for res in data["data"]:
                result[res["id"]] = {
                    "source":        res["sender"],
                    "dest":          res["recipient"],
                    "amount":        int(res["amount"]),
                    "comment":       res["vendorField"] if "vendorField" in res else "",
                    "confirmations": int(res["confirmations"]),
                    "fee":           int(res["fee"]),
                    "ts":            int(res["timestamp"]["unix"])
                }
                if "type" in res and res["type"] in self.transactions_type_mapping:
                    result[res["id"]]["type"] = self.transactions_type_mapping[res["type"]]
                
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
                    self.config = self.owner.config_load(file="HYD.cfg", default=BlockchainTokenHYD.DEFAULT_CONFIG)
 
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
                    self.owner.config_save(file="HYD.cfg", config=self.config)

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
