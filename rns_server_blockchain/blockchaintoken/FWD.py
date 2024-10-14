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


class BlockchainTokenFWD():

    def __init__(self, owner, name):
        self.owner = owner
        self.name = name

        self.token = {
            "FWD": {},
        }


    #################################################
    # Accounts                                      #
    #################################################


    def accounts_add(self, token, data):
        raise ValueError("Not implemented")


    def accounts_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def accounts_get(self, token, account_id):
        raise ValueError("Not implemented")


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
        pass


    def connection_response_stop(self, token):
        pass


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
        raise ValueError("Not implemented")


    def transactions_count(self, token, filter, search):
        raise ValueError("Not implemented")


    def transactions_get(self, token, account_id, ts):
        result = {}

        return result


    def transactions_list(self, token, filter, search, order, limit, limit_start):
        raise ValueError("Not implemented")
