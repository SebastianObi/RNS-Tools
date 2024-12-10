#!/usr/bin/env python3
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


##############################################################################################################
# Include


#### System ####
import sys
import os
import time
import datetime
import argparse

#### UID ####
import uuid

#### Config ####
import configparser

#### Process ####
import signal
import threading
import subprocess

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### UID ####
import string, random

#### Token ####
import importlib


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Blockchain"
DESCRIPTION = "Gateway/Bridge for payment/wallet for RNS based apps"
VERSION = "0.0.1 (2024-10-07)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
RNS_SERVER_BLOCKCHAIN = None

MSG_FIELD_EMBEDDED_LXMS    = 0x01
MSG_FIELD_TELEMETRY        = 0x02
MSG_FIELD_TELEMETRY_STREAM = 0x03
MSG_FIELD_ICON             = 0x04
MSG_FIELD_FILE_ATTACHMENTS = 0x05
MSG_FIELD_IMAGE            = 0x06
MSG_FIELD_AUDIO            = 0x07
MSG_FIELD_THREAD           = 0x08
MSG_FIELD_COMMANDS         = 0x09
MSG_FIELD_RESULTS          = 0x0A

MSG_FIELD_ANSWER             = 0xA0
MSG_FIELD_ATTACHMENT         = 0xA1
MSG_FIELD_COMMANDS_EXECUTE   = 0xA2
MSG_FIELD_COMMANDS_RESULT    = 0xA3
MSG_FIELD_CONTACT            = 0xA4
MSG_FIELD_DATA               = 0xA5
MSG_FIELD_DELETE             = 0xA6
MSG_FIELD_EDIT               = 0xA7
MSG_FIELD_GROUP              = 0xA8
MSG_FIELD_HASH               = 0xA9
MSG_FIELD_ICON_MENU          = 0xAA
MSG_FIELD_ICON_SRC           = 0xAB
MSG_FIELD_KEYBOARD           = 0xAC
MSG_FIELD_KEYBOARD_INLINE    = 0xAD
MSG_FIELD_LOCATION           = 0xAE
MSG_FIELD_OWNER              = 0xC0
MSG_FIELD_POLL               = 0xAF
MSG_FIELD_POLL_ANSWER        = 0xB0
MSG_FIELD_REACTION           = 0xB1
MSG_FIELD_RECEIPT            = 0xB2
MSG_FIELD_SCHEDULED          = 0xB3
MSG_FIELD_SILENT             = 0xB4
MSG_FIELD_SRC                = 0xB5
MSG_FIELD_STATE              = 0xB6
MSG_FIELD_STICKER            = 0xB7
MSG_FIELD_TELEMETRY_DB       = 0xB8
MSG_FIELD_TELEMETRY_PEER     = 0xB9
MSG_FIELD_TELEMETRY_COMMANDS = 0xBA
MSG_FIELD_TEMPLATE           = 0xBB
MSG_FIELD_TOPIC              = 0xBC
MSG_FIELD_TYPE               = 0xBD
MSG_FIELD_TYPE_FIELDS        = 0xBE
MSG_FIELD_VOICE              = 0xBF


##############################################################################################################
# RateLimiter Class


class RateLimiter:
    def __init__(self, calls, size, duration):
        self.calls = calls
        self.size = size
        self.duration = duration
        self.ts = time.time()
        self.data_calls = {}
        self.data_size = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._jobs, daemon=True).start()


    def handle(self, id):
        if self.handle_call(id) and self.handle_size(id, 0):
            return True
        else:
            return False


    def handle_call(self, id):
        with self.lock:
            if self.calls == 0:
                return True
            if id not in self.data_calls:
                self.data_calls[id] = []
            self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
            if len(self.data_calls[id]) >= self.calls:
                return False
            else:
                self.data_calls[id].append(self.ts)
                return True


    def handle_size(self, id, size):
        with self.lock:
            if self.size == 0:
                return True
            if id not in self.data_size:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][1] <= self.ts - self.duration:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][0] >= self.size:
                return False
            else:
                self.data_size[id][0] += size
                self.data_size[id][1] = self.ts
                return True


    def _jobs(self):
        while True:
            time.sleep(self.duration)
            self.ts = time.time()
            with self.lock:
                if self.calls > 0:
                    for id in list(self.data_calls.keys()):
                        self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
                        if not self.data_calls[id]:
                            del self.data_calls[id]

                if self.size > 0:
                    for id in list(self.data_size.keys()):
                        if self.data_size[id][1] <= self.ts - self.duration:
                            del self.data_size[id]


##############################################################################################################
# ServerBlockchain Class


class ServerBlockchain:
    ACCOUNT_STATE_FAILED      = 0x00 # Failed
    ACCOUNT_STATE_SUCCESSFULL = 0x01 # Successfull
    ACCOUNT_STATE_WAITING     = 0x02 # Waiting in local cache
    ACCOUNT_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    ACCOUNT_STATE_PROCESSING  = 0x04 # Processing/Execution on the blockchain
    ACCOUNT_STATE_FAILED_TMP  = 0x05 # Temporary failed

    CONNECTION_TIMEOUT = 10 # Seconds

    DELEGATE_STATE_RESIGNED = 0x00
    DELEGATE_STATE_ACTIVE   = 0x01
    DELEGATE_STATE_STANDBY  = 0x02

    JOBS_PERIODIC_DELAY    = 10 # Seconds
    JOBS_PERIODIC_INTERVAL = 60 # Seconds

    KEY_RESULT        = 0x0A # Result
    KEY_RESULT_REASON = 0x0B # Result - Reason
    KEY_A             = 0x0C # Account
    KEY_API           = 0x0D # API
    KEY_B             = 0x0E # Block
    KEY_D             = 0x0F # Delegate
    KEY_E             = 0x10 # Explorer
    KEY_I             = 0x11 # Info
    KEY_T             = 0x12 # Transaction

    KEY_A_BALANCE      = 0x00
    KEY_A_DATA         = 0x01
    KEY_A_DELEGATE     = 0x02
    KEY_A_ID           = 0x03
    KEY_A_KEY          = 0x04
    KEY_A_METADATA     = 0x05
    KEY_A_NAME         = 0x06
    KEY_A_NONCE        = 0x07
    KEY_A_STATE        = 0x08
    KEY_A_STATE_REASON = 0x09
    KEY_A_TOKEN        = 0x0A
    KEY_A_TS           = 0x0B
    KEY_A_VOTE         = 0x0C

    KEY_A_MAPPING = {
        "balance":      KEY_A_BALANCE,
        "data":         KEY_A_DATA,
        "delegate":     KEY_A_DELEGATE,
        "id":           KEY_A_ID,
        "key":          KEY_A_KEY,
        "name":         KEY_A_NAME,
        "nonce":        KEY_A_NONCE,
        "state":        KEY_A_STATE,
        "state_reason": KEY_A_STATE_REASON,
        "token":        KEY_A_TOKEN,
        "ts":           KEY_A_TS,
        "vote":         KEY_A_VOTE,
    }

    KEY_A_STATE_REASON_None                              = 0x00
    KEY_A_STATE_REASON_WalletIndexAlreadyRegisteredError = 0x01
    KEY_A_STATE_REASON_WalletIndexNotFoundError          = 0x02

    KEY_B_CONFIRMATIONS  = 0x00
    KEY_B_DATA           = 0x01
    KEY_B_FORGED_AMOUNT  = 0x02
    KEY_B_FORGED_FEE     = 0x03
    KEY_B_FORGED_REWARD  = 0x04
    KEY_B_FORGED_TOTAL   = 0x05
    KEY_B_GENERATOR_ID   = 0x06
    KEY_B_GENERATOR_NAME = 0x07
    KEY_B_HEIGHT         = 0x08
    KEY_B_ID             = 0x09
    KEY_B_TRANSACTIONS   = 0x0A
    KEY_B_TS             = 0x0B

    KEY_B_MAPPING = {
        "confirmations":  KEY_B_CONFIRMATIONS,
        "data":           KEY_B_DATA,
        "forged_amount":  KEY_B_FORGED_AMOUNT,
        "forged_fee":     KEY_B_FORGED_FEE,
        "forged_reward":  KEY_B_FORGED_REWARD,
        "forged_total":   KEY_B_FORGED_TOTAL,
        "generator_id":   KEY_B_GENERATOR_ID,
        "generator_name": KEY_B_GENERATOR_NAME,
        "height":         KEY_B_HEIGHT,
        "id":             KEY_B_ID,
        "transactions":   KEY_B_TRANSACTIONS,
        "ts":             KEY_B_TS,
    }

    KEY_D_BLOCK_ID      = 0x00
    KEY_D_BLOCK_TS      = 0x01
    KEY_D_DATA          = 0x02
    KEY_D_DATA_HASH     = 0x03
    KEY_D_FORGED_AMOUNT = 0x04
    KEY_D_FORGED_BLOCKS = 0x05
    KEY_D_FORGED_FEE    = 0x06
    KEY_D_FORGED_REWARD = 0x07
    KEY_D_FORGED_TOTAL  = 0x08
    KEY_D_ID            = 0x09
    KEY_D_NAME          = 0x0A
    KEY_D_NAME_HASH     = 0x0B
    KEY_D_STATE         = 0x0C
    KEY_D_STATE_HASH    = 0x0D
    KEY_D_VALUE         = 0x0E
    KEY_D_VALUE_HASH    = 0x0F
    KEY_D_VOTES         = 0x10
    KEY_D_VOTES_PERCENT = 0x11

    KEY_D_MAPPING = {
        "block_id":      KEY_D_BLOCK_ID,
        "block_ts":      KEY_D_BLOCK_TS,
        "data":          KEY_D_DATA,
        "data_hash":     KEY_D_DATA_HASH,
        "forged_amount": KEY_D_FORGED_AMOUNT,
        "forged_blocks": KEY_D_FORGED_BLOCKS,
        "forged_fee":    KEY_D_FORGED_FEE,
        "forged_reward": KEY_D_FORGED_REWARD,
        "forged_total":  KEY_D_FORGED_TOTAL,
        "id":            KEY_D_ID,
        "name":          KEY_D_NAME,
        "name_hash":     KEY_D_NAME_HASH,
        "state":         KEY_D_STATE,
        "state_hash":    KEY_D_STATE_HASH,
        "value":         KEY_D_VALUE,
        "value_hash":    KEY_D_VALUE_HASH,
        "votes":         KEY_D_VOTES,
        "votes_percent": KEY_D_VOTES_PERCENT,
    }

    KEY_E_FILTER      = 0x00
    KEY_E_HASH        = 0x01
    KEY_E_LIMIT       = 0x02
    KEY_E_LIMIT_START = 0x03
    KEY_E_ORDER       = 0x04
    KEY_E_SEARCH      = 0x05
    KEY_E_TOKEN       = 0x06

    KEY_E_MAPPING = {
        "filter":      KEY_E_FILTER,
        "hash":        KEY_E_HASH,
        "limit":       KEY_E_LIMIT,
        "limit_start": KEY_E_LIMIT_START,
        "order":       KEY_E_ORDER,
        "search":      KEY_E_SEARCH,
        "token":       KEY_E_TOKEN,
    }

    KEY_E_ORDER_ASC  = 0x00
    KEY_E_ORDER_DESC = 0x01

    KEY_E_ORDER_MAPPING = {
        "asc":  KEY_E_ORDER_ASC,
        "desc": KEY_E_ORDER_DESC,
    }

    KEY_I_DATA         = 0x00
    KEY_I_SUPPLY       = 0x01

    KEY_I_MAPPING = {
        "account":      KEY_A,
        "block":        KEY_B,
        "delegate":     KEY_D,
        "transaction":  KEY_T,
        "data":         KEY_I_DATA,
        "supply":       KEY_I_SUPPLY,
    }

    KEY_T_AMOUNT        = 0x00
    KEY_T_BLOCK_ID      = 0x01
    KEY_T_COMMENT       = 0x02
    KEY_T_CONFIRMATIONS = 0x03
    KEY_T_DATA          = 0x04
    KEY_T_DEST          = 0x05
    KEY_T_DIRECTION     = 0x06
    KEY_T_FEE           = 0x07
    KEY_T_ID            = 0x08
    KEY_T_INDEX         = 0x09
    KEY_T_METADATA      = 0x0A
    KEY_T_NONCE         = 0x0B
    KEY_T_SOURCE        = 0x0C
    KEY_T_STATE         = 0x0D
    KEY_T_STATE_REASON  = 0x0E
    KEY_T_TS            = 0x0F
    KEY_T_TYPE          = 0x10

    KEY_T_MAPPING = {
        "amount":        KEY_T_AMOUNT,
        "block_id":      KEY_T_BLOCK_ID,
        "comment":       KEY_T_COMMENT,
        "confirmations": KEY_T_CONFIRMATIONS,
        "data":          KEY_T_DATA,
        "dest":          KEY_T_DEST,
        "direction":     KEY_T_DIRECTION,
        "fee":           KEY_T_FEE,
        "id":            KEY_T_ID,
        "index":         KEY_T_INDEX,
        "nonce":         KEY_T_NONCE,
        "source":        KEY_T_SOURCE,
        "state":         KEY_T_STATE,
        "state_reason":  KEY_T_STATE_REASON,
        "ts":            KEY_T_TS,
        "type":          KEY_T_TYPE,
    }

    KEY_T_STATE_REASON_None                                      = 0x00
    KEY_T_STATE_REASON_AlreadyVotedError                         = 0x01
    KEY_T_STATE_REASON_ColdWalletError                           = 0x02
    KEY_T_STATE_REASON_DeactivatedTransactionHandlerError        = 0x03
    KEY_T_STATE_REASON_HtlcLockExpiredError                      = 0x04
    KEY_T_STATE_REASON_HtlcLockNotExpiredError                   = 0x05
    KEY_T_STATE_REASON_HtlcLockTransactionNotFoundError          = 0x06
    KEY_T_STATE_REASON_HtlcSecretHashMismatchError               = 0x07
    KEY_T_STATE_REASON_InsufficientBalanceError                  = 0x08
    KEY_T_STATE_REASON_InvalidMultiSignatureError                = 0x09
    KEY_T_STATE_REASON_InvalidMultiSignaturesError               = 0x0A
    KEY_T_STATE_REASON_InvalidSecondSignatureError               = 0x0B
    KEY_T_STATE_REASON_InvalidTransactionTypeError               = 0x0C
    KEY_T_STATE_REASON_IpfsHashAlreadyExists                     = 0x0D
    KEY_T_STATE_REASON_LegacyMultiSignatureError                 = 0x0E
    KEY_T_STATE_REASON_LegacyMultiSignatureRegistrationError     = 0x0F
    KEY_T_STATE_REASON_MissingMultiSignatureOnSenderError        = 0x10
    KEY_T_STATE_REASON_MultiSignatureAlreadyRegisteredError      = 0x11
    KEY_T_STATE_REASON_MultiSignatureKeyCountMismatchError       = 0x12
    KEY_T_STATE_REASON_MultiSignatureMinimumKeysError            = 0x13
    KEY_T_STATE_REASON_NotEnoughDelegatesError                   = 0x14
    KEY_T_STATE_REASON_NotImplementedError                       = 0x15
    KEY_T_STATE_REASON_NotSupportedForMultiSignatureWalletError  = 0x16
    KEY_T_STATE_REASON_NoVoteError                               = 0x17
    KEY_T_STATE_REASON_SecondSignatureAlreadyRegisteredError     = 0x18
    KEY_T_STATE_REASON_SenderWalletMismatchError                 = 0x19
    KEY_T_STATE_REASON_UnexpectedNonceError                      = 0x1A
    KEY_T_STATE_REASON_UnexpectedSecondSignatureError            = 0x1B
    KEY_T_STATE_REASON_UnsupportedMultiSignatureTransactionError = 0x1C
    KEY_T_STATE_REASON_UnvoteMismatchError                       = 0x1D
    KEY_T_STATE_REASON_VotedForNonDelegateError                  = 0x1E
    KEY_T_STATE_REASON_VotedForResignedDelegateError             = 0x1F
    KEY_T_STATE_REASON_WalletAlreadyResignedError                = 0x20
    KEY_T_STATE_REASON_WalletIsAlreadyDelegateError              = 0x21
    KEY_T_STATE_REASON_WalletNotADelegateError                   = 0x22
    KEY_T_STATE_REASON_WalletNoUsernameError                     = 0x23
    KEY_T_STATE_REASON_WalletUsernameAlreadyRegisteredError      = 0x24

    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_USER     = 0x04
    RESULT_NO_RIGHT    = 0x05
    RESULT_NO_DATA     = 0x06
    RESULT_LIMIT_ALL   = 0x07
    RESULT_LIMIT_PEER  = 0x08
    RESULT_PARTIAL     = 0x09
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF

    STATE_NO_PATH            = 0x00
    STATE_PATH_REQUESTED     = 0x01
    STATE_ESTABLISHING_LINK  = 0x02
    STATE_LINK_TIMEOUT       = 0x03
    STATE_LINK_ESTABLISHED   = 0x04
    STATE_REQUESTING         = 0x05
    STATE_REQUEST_SENT       = 0x06
    STATE_REQUEST_FAILED     = 0x07
    STATE_REQUEST_TIMEOUT    = 0x08
    STATE_RECEIVING_RESPONSE = 0x09
    STATE_TRANSFERRING       = 0x0A
    STATE_DISCONECTED        = 0xFD
    STATE_DONE               = 0xFF

    TRANSACTION_STATE_FAILED      = 0x00 # Failed
    TRANSACTION_STATE_SUCCESSFULL = 0x01 # Successfull
    TRANSACTION_STATE_WAITING     = 0x02 # Waiting in local cache
    TRANSACTION_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    TRANSACTION_STATE_PROCESSING  = 0x04 # Processing/Execution on the blockchain
    TRANSACTION_STATE_FAILED_TMP  = 0x05 # Temporary failed

    TRANSACTION_TYPE_TRANSFER                 = 0x00
    TRANSACTION_TYPE_SWAP                     = 0x01
    TRANSACTION_TYPE_VOTE                     = 0x02
    TRANSACTION_TYPE_UNVOTE                   = 0x03
    TRANSACTION_TYPE_DELEGATE_REGISTRATION    = 0x04
    TRANSACTION_TYPE_DELEGATE_RESIGNATION     = 0x05
    TRANSACTION_TYPE_SECOND_SIGNATURE         = 0x06
    TRANSACTION_TYPE_MULTI_SIGNATURE          = 0x07
    TRANSACTION_TYPE_MULTI_PAYMENT            = 0x08
    TRANSACTION_TYPE_IPFS                     = 0x09
    TRANSACTION_TYPE_TIMELOCK_TRANSFER        = 0x0A
    TRANSACTION_TYPE_TIMELOCK_CLAIM           = 0x0B
    TRANSACTION_TYPE_TIMELOCK_REFUND          = 0x0C
    TRANSACTION_TYPE_BUSINESS_REGISTRATION    = 0x0D
    TRANSACTION_TYPE_BUSINESS_RESIGNATION     = 0x0E
    TRANSACTION_TYPE_BUSINESS_UPDATE          = 0x0F
    TRANSACTION_TYPE_BRIDGECHAIN_REGISTRATION = 0x10
    TRANSACTION_TYPE_BRIDGECHAIN_RESIGNATION  = 0x11
    TRANSACTION_TYPE_BRIDGECHAIN_UPDATE       = 0x12
    TRANSACTION_TYPE_SSI_TRANSACTION          = 0x13
    TRANSACTION_TYPE_DNS_TRANSACTION          = 0x14

    TYPE_API      = 0x00
    TYPE_EXPLORER = 0x01
    TYPE_WALLET   = 0x02
    TYPE_UNKNOWN  = 0xFF


    def __init__(self, storage_path=None, identity_file="identity", identity=None, ratchets=False,
                 destination_name="nomadnetwork", destination_type="bc",
                 announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False,
                 register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30,
                 limiter_server_enabled=False, limiter_server_calls=1000, limiter_server_size=0, limiter_server_duration=60,
                 limiter_peer_enabled=True, limiter_peer_calls=15, limiter_peer_size=500*1024, limiter_peer_duration=60,
                 limiter_api_enabled=False, limiter_api_calls=15, limiter_api_size=500*1024, limiter_api_duration=60,
                 limiter_explorer_enabled=False, limiter_explorer_calls=15, limiter_explorer_size=500*1024, limiter_explorer_duration=60,
                 limiter_wallet_enabled=False, limiter_wallet_calls=15, limiter_wallet_size=500*1024, limiter_wallet_duration=60,
        ):

        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity
        self.ratchets = ratchets

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        if self.storage_path:
            if not os.path.isdir(self.storage_path):
                os.makedirs(self.storage_path)
                RNS.log("Server - Storage path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Storage path: " + self.storage_path, RNS.LOG_INFO)

        if self.identity:
            RNS.log("Server - Using existing Primary Identity %s" % (str(self.identity)))
        else:
            if not self.storage_path:
                RNS.log("Server - No storage_path parameter", RNS.LOG_ERROR)
                return
            if not self.identity_file:
                self.identity_file = "identity"
            self.identity_path = self.storage_path + "/" + self.identity_file
            if os.path.isfile(self.identity_path):
                try:
                    self.identity = RNS.Identity.from_file(self.identity_path)
                    if self.identity != None:
                        RNS.log("Server - Loaded Primary Identity %s from %s" % (str(self.identity), self.identity_path))
                    else:
                        RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                except Exception as e:
                    RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)
            else:
                try:
                    RNS.log("Server - No Primary Identity file found, creating new...")
                    self.identity = RNS.Identity()
                    self.identity.to_file(self.identity_path)
                    RNS.log("Server - Created new Primary Identity %s" % (str(self.identity)))
                except Exception as e:
                    RNS.log("Server - Could not create and save a new Primary Identity", RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, self.destination_name, self.destination_type)

        if self.ratchets:
            self.destination.enable_ratchets(self.identity_path+"."+RNS.hexrep(self.destination.hash, delimit=False)+".ratchets")

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        self.destination.set_link_established_callback(self.peer_connected)

        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        self.register()

        self.token_init()

        if limiter_server_enabled:
            self.limiter_server = RateLimiter(int(limiter_server_calls), int(limiter_server_size), int(limiter_server_duration))
        else:
            self.limiter_server = None

        if limiter_peer_enabled:
            self.limiter_peer = RateLimiter(int(limiter_peer_calls), int(limiter_peer_size), int(limiter_peer_duration))
        else:
            self.limiter_peer = None

        if limiter_api_enabled:
            self.limiter_api = RateLimiter(int(limiter_api_calls), int(limiter_api_size), int(limiter_api_duration))
        else:
            self.limiter_api = None

        if limiter_explorer_enabled:
            self.limiter_explorer = RateLimiter(int(limiter_explorer_calls), int(limiter_explorer_size), int(limiter_explorer_duration))
        else:
            self.limiter_explorer = None

        if limiter_wallet_enabled:
            self.limiter_wallet = RateLimiter(int(limiter_wallet_calls), int(limiter_wallet_size), int(limiter_wallet_duration))
        else:
            self.limiter_wallet = None


    def start(self):
        pass

    def stop(self):
        pass


    def register_announce_callback(self, handler_function):
        self.announce_callback = handler_function(self.aspect_filter)
        RNS.Transport.register_announce_handler(self.announce_callback)


    def destination_hash(self):
        return self.destination.hash


    def destination_hash_str(self):
        return RNS.hexrep(self.destination.hash, False)


    def destination_check(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                RNS.log("Server - Destination length is invalid", RNS.LOG_ERROR)
                return False

            try:    
                destination = bytes.fromhex(destination)
            except Exception as e:
                RNS.log("Server - Destination is invalid", RNS.LOG_ERROR)
                return False

        return True


    def destination_correct(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                return ""

            try:
                destination_bytes = bytes.fromhex(destination)
                return destination
            except Exception as e:
                return ""

        return ""


    def announce(self, app_data=None, attached_interface=None, initial=False):
        announce_timer = None

        if self.announce_periodic and self.announce_periodic_interval > 0:
            announce_timer = threading.Timer(self.announce_periodic_interval*60, self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if initial:
            if self.announce_startup:
                if self.announce_startup_delay > 0:
                    if announce_timer is not None:
                        announce_timer.cancel()
                    announce_timer = threading.Timer(self.announce_startup_delay, self.announce)
                    announce_timer.daemon = True
                    announce_timer.start()
                else:
                    self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        if self.announce_hidden:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", RNS.LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + app_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)
        else:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + self.announce_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(self.announce_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)


    def register(self):
        RNS.log("Server - Register", RNS.LOG_DEBUG)
        self.destination.register_request_handler("api", response_generator=self.response_api, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("explorer", response_generator=self.response_explorer, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("wallet", response_generator=self.response_wallet, allow=RNS.Destination.ALLOW_ALL)


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)

        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()


    #################################################
    # Config                                        #
    #################################################


    def config_load(self, file, default=""):
        try:
            file = self.storage_path+"/"+file

            config = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
            config.sections()

            if os.path.isfile(file):
                config.read(file, encoding="utf-8")
                return config
            else:
                if not os.path.isdir(os.path.dirname(file)):
                    os.makedirs(os.path.dirname(file))

                fh = open(file, "w")
                fh.write(default)
                fh.close()

                config.read(file, encoding="utf-8")
                return config
        except Exception as e:
            return None


    def config_save(self, file, config):  
        try:
            file = self.storage_path+"/"+file

            if not os.path.isdir(os.path.dirname(file)):
                os.makedirs(os.path.dirname(file))

            fh = open(file, "w")
            config.write(fh)
            fh.close()
            return True
        except Exception as e:
            return False


    #################################################
    # Log                                           #
    #################################################


    def log(self, text="", level=None):
        if level == None:
            level = RNS.LOG_ERROR

        RNS.log(text, level)


    def log_exception(self, e, text="", level=None):
        import traceback

        if level == None:
            level = RNS.LOG_ERROR

        RNS.log(text+" - An "+str(type(e))+" occurred: "+str(e), level)
        RNS.log("".join(traceback.TracebackException.from_exception(e).format()), level)


    #################################################
    # Response                                      #
    #################################################


    def response_api(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if self.limiter_api and not self.limiter_api.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        RNS.log("Server - Response - API", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if self.KEY_API in data:
            data_return[self.KEY_API] = {}
            for key, value in data[self.KEY_API].items():
                try:
                    value_token = value["token"] if "token" in value else None
                    value_url = value["url"] if "url" in value else None
                    value_data = value["data"] if "data" in value else None
                    value_json = value["json"] if "json" in value else None
                    value_headers = value["headers"] if "headers" in value else None
                    value_cookies = value["cookies"] if "cookies" in value else None
                    value_auth = value["auth"] if "auth" in value else None
                    value_timeout = value["timeout"] if "timeout" in value else None

                    if "delete" in value:
                        response = self.api_delete(token=value_token, url=value_url if value_url else value["delete"], data=value_data, json=value_json, headers=value_headers, cookies=value_cookies, auth=value_auth, timeout=value_timeout)
                    elif "get" in value:
                        response = self.api_get(token=value_token, url=value_url if value_url else value["get"], data=value_data, json=value_json, headers=value_headers, cookies=value_cookies, auth=value_auth, timeout=value_timeout)
                    elif "patch" in value:
                        response = self.api_patch(token=value_token, url=value_url if value_url else value["patch"], data=value_data, json=value_json, headers=value_headers, cookies=value_cookies, auth=value_auth, timeout=value_timeout)
                    elif "post" in value:
                        response = self.api_post(token=value_token, url=value_url if value_url else value["post"], data=value_data, json=value_json, headers=value_headers, cookies=value_cookies, auth=value_auth, timeout=value_timeout)
                    elif "put" in value:
                        response = self.api_put(token=value_token, url=value_url if value_url else value["put"], data=value_data, json=value_json, headers=value_headers, cookies=value_cookies, auth=value_auth, timeout=value_timeout)
                    else:
                        raise ValueError("Wrong api type")
                    data_return[self.KEY_API][key] = response
                except Exception as e:
                    self.log_exception(e, "Server - API")
                    data_return[self.KEY_API][key] = None
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL
            if len(data_return[self.KEY_API]) == 0:
                del data_return[self.KEY_API]

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    def response_explorer(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if self.limiter_explorer and not self.limiter_explorer.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        RNS.log("Server - Response - Explorer", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if self.KEY_E in data:
            # explorer
            data_explorer = data[self.KEY_E]
            filter = data_explorer[self.KEY_E_FILTER] if self.KEY_E_FILTER in data_explorer else None
            hash = data_explorer[self.KEY_E_HASH] if self.KEY_E_HASH in data_explorer else None
            limit = data_explorer[self.KEY_E_LIMIT] if self.KEY_E_LIMIT in data_explorer else None
            limit_start = data_explorer[self.KEY_E_LIMIT_START] if self.KEY_E_LIMIT_START in data_explorer else None
            order = data_explorer[self.KEY_E_ORDER] if self.KEY_E_ORDER in data_explorer else None
            search = data_explorer[self.KEY_E_SEARCH] if self.KEY_E_SEARCH in data_explorer else None
            token = data_explorer[self.KEY_E_TOKEN] if self.KEY_E_TOKEN in data_explorer else None

            if self.KEY_A in data:
                mapping = {v: k for k, v in self.KEY_A_MAPPING.items()}
            elif self.KEY_B in data:
                mapping = {v: k for k, v in self.KEY_B_MAPPING.items()}
            elif self.KEY_D in data:
                mapping = {v: k for k, v in self.KEY_D_MAPPING.items()}
            elif self.KEY_I in data:
                mapping = {v: k for k, v in self.KEY_I_MAPPING.items()}
            elif self.KEY_T in data:
                mapping = {v: k for k, v in self.KEY_T_MAPPING.items()}
            else:
                mapping = {}

            # explorer - filter
            if filter != None and len(filter) > 0:
                filter_result = {}
                for filter_key, filter_value in filter.items():
                    if filter_key in mapping:
                        filter_result[mapping[filter_key]] = filter_value
                if len(filter_result) > 0:
                    filter = filter_result
                else:
                    filter = None

            # explorer - order
            if order != None:
                order_mapping = {v: k for k, v in self.KEY_E_ORDER_MAPPING.items()}
                order[1] = order_mapping[order[1]]
                if order[0] in mapping:
                    order[0] = mapping[order[0]]
                else:
                    order = None

            # accounts
            if self.KEY_A in data:
                try:
                    count, entrys = self.accounts_list(token=token, filter=filter, search=search, order=order, limit=limit, limit_start=limit_start)
                    accounts = {}
                    for account_id, result in entrys.items():
                        accounts[account_id] = {}
                        for key, value in result.items():
                            if key in self.KEY_A_MAPPING:
                                accounts[account_id][self.KEY_A_MAPPING[key]] = value
                    hash_new = RNS.Identity.full_hash(msgpack.packb(accounts))
                    if hash != hash_new:
                        data_return[self.KEY_A] = [count, accounts]
                        data_return[self.KEY_E] = {self.KEY_E_HASH: hash_new}
                except Exception as e:
                    self.log_exception(e, "Server - Explorer - Accounts")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            # blocks
            if self.KEY_B in data:
                try:
                    count, entrys = self.blocks_list(token=token, filter=filter, search=search, order=order, limit=limit, limit_start=limit_start)
                    blocks = {}
                    for blocks_id, result in entrys.items():
                        blocks[blocks_id] = {}
                        for key, value in result.items():
                            if key in self.KEY_B_MAPPING:
                                blocks[blocks_id][self.KEY_B_MAPPING[key]] = value
                    hash_new = RNS.Identity.full_hash(msgpack.packb(blocks))
                    if hash != hash_new:
                        data_return[self.KEY_B] = [count, blocks]
                        data_return[self.KEY_E] = {self.KEY_E_HASH: hash_new}
                except Exception as e:
                    self.log_exception(e, "Server - Explorer - Blocks")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            # delegates
            if self.KEY_D in data:
                try:
                    count, entrys = self.delegates_list(token=token, filter=filter, search=search, order=order, limit=limit, limit_start=limit_start)
                    delegates = {}
                    for delegate_id, result in entrys.items():
                        delegates[delegate_id] = {}
                        for key, value in result.items():
                            if key in self.KEY_D_MAPPING:
                                delegates[delegate_id][self.KEY_D_MAPPING[key]] = value
                    hash_new = RNS.Identity.full_hash(msgpack.packb(delegates))
                    if hash != hash_new:
                        data_return[self.KEY_D] = [count, delegates]
                        data_return[self.KEY_E] = {self.KEY_E_HASH: hash_new}
                except Exception as e:
                    self.log_exception(e, "Server - Explorer - Delegates")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            # infos
            if self.KEY_I in data:
                try:
                    count, entrys = self.infos_list(token=token, filter=filter, search=search, order=order, limit=limit, limit_start=limit_start)
                    infos = {}
                    for info_id, result in entrys.items():
                        infos[info_id] = {}
                        for key, value in result.items():
                            if key in self.KEY_I_MAPPING:
                                if self.KEY_I_MAPPING[key] == self.KEY_A:
                                    infos[info_id][self.KEY_I_MAPPING[key]] = {}
                                    for value_key, value_value in value.items():
                                        if value_key in self.KEY_A_MAPPING:
                                            infos[info_id][self.KEY_I_MAPPING[key]][self.KEY_A_MAPPING[value_key]] = value_value
                                elif self.KEY_I_MAPPING[key] == self.KEY_B:
                                    infos[info_id][self.KEY_I_MAPPING[key]] = {}
                                    for value_key, value_value in value.items():
                                        if value_key in self.KEY_B_MAPPING:
                                            infos[info_id][self.KEY_I_MAPPING[key]][self.KEY_B_MAPPING[value_key]] = value_value
                                elif self.KEY_I_MAPPING[key] == self.KEY_D:
                                    infos[info_id][self.KEY_I_MAPPING[key]] = {}
                                    for value_key, value_value in value.items():
                                        if value_key in self.KEY_D_MAPPING:
                                            infos[info_id][self.KEY_I_MAPPING[key]][self.KEY_D_MAPPING[value_key]] = value_value
                                elif self.KEY_I_MAPPING[key] == self.KEY_T:
                                    infos[info_id][self.KEY_I_MAPPING[key]] = {}
                                    for value_key, value_value in value.items():
                                        if value_key in self.KEY_T_MAPPING:
                                            infos[info_id][self.KEY_I_MAPPING[key]][self.KEY_T_MAPPING[value_key]] = value_value
                                else:
                                    infos[info_id][self.KEY_I_MAPPING[key]] = value
                    hash_new = RNS.Identity.full_hash(msgpack.packb(infos))
                    if hash != hash_new:
                        data_return[self.KEY_I] = [count, infos]
                        data_return[self.KEY_E] = {self.KEY_E_HASH: hash_new}
                except Exception as e:
                    self.log_exception(e, "Server - Explorer - Infos")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            # transactions
            if self.KEY_T in data:
                try:
                    count, entrys = self.transactions_list(token=token, filter=filter, search=search, order=order, limit=limit, limit_start=limit_start)
                    transactions = {}
                    for transaction_id, result in entrys.items():
                        transactions[transaction_id] = {}
                        for key, value in result.items():
                            if key in self.KEY_T_MAPPING:
                                transactions[transaction_id][self.KEY_T_MAPPING[key]] = value
                    hash_new = RNS.Identity.full_hash(msgpack.packb(transactions))
                    if hash != hash_new:
                        data_return[self.KEY_T] = [count, transactions]
                        data_return[self.KEY_E] = {self.KEY_E_HASH: hash_new}
                except Exception as e:
                    self.log_exception(e, "Server - Explorer - Transactions")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    def response_wallet(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if self.limiter_wallet and not self.limiter_wallet.handle(str(remote_identity)):
            return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        RNS.log("Server - Response - Wallet", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        def token_connection_response_start(token_connection, token):
            if token not in token_connection:
                token_connection.append(token)
                self.connection_response_start(token=token)
            return token_connection

        def token_connection_response_stop(token_connection):
            for token in token_connection:
                self.connection_response_stop(token=token)
            return token_connection

        token_connection = []

        data_return = {}

        data_return[self.KEY_RESULT] = self.RESULT_OK

        # accounts
        if self.KEY_A in data:
            data_return[self.KEY_A] = {}

            for account_id, account in data[self.KEY_A].items():
                token = account[self.KEY_A_TOKEN]
                token_connection = token_connection_response_start(token_connection=token_connection, token=token)

                # accounts_add - New account
                if self.KEY_A_STATE in account:
                    try:
                        result = self.accounts_add(
                            token=token,
                            data=account[self.KEY_A_DATA] if self.KEY_A_DATA in account else None
                        )
                        account_id_new = result["account_id"] if "account_id" in result else account_id
                        data_return[self.KEY_A][account_id_new] = {
                            self.KEY_A_STATE: result["state"] if "state" in result else self.ACCOUNT_STATE_SUCCESSFULL
                        }
                        if account_id_new != account_id:
                            data_return[self.KEY_A][account_id_new][self.KEY_A_ID] = account_id
                        if "data" in result and result["data"] != None and len(result["data"]) > 0:
                            data_return[self.KEY_A][account_id_new][self.KEY_A_DATA] = result["data"]
                        if "state_reason" in result:
                            data_return[self.KEY_A][account_id_new][self.KEY_A_STATE_REASON] = result["state_reason"]
                        account_id = account_id_new
                    except Exception as e:
                        self.log_exception(e, "Server - Wallet - New account")
                        data_return[self.KEY_A][account_id] = {
                            self.KEY_A_STATE: self.ACCOUNT_STATE_FAILED_TMP
                        }
                        data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

                # accounts_get - Existing account
                else:
                    data_return[self.KEY_A][account_id] = {}

                transactions = {}

                # transactions_get - Existing transaction
                try:
                    ts = account[self.KEY_A_TS] if self.KEY_A_TS in account else 0
                    for transaction_id, result in self.transactions_get(token=token, account_id=account_id, ts=ts).items():
                        transactions[transaction_id] = {
                            self.KEY_T_AMOUNT: result["amount"],
                            self.KEY_T_TS: result["ts"],
                        }
                        if result["source"] != account_id:
                            transactions[transaction_id][self.KEY_T_SOURCE] = result["source"]
                        if result["dest"] != account_id:
                            transactions[transaction_id][self.KEY_T_DEST] = result["dest"]
                        if "fee" in result and result["fee"] != None and result["fee"] > 0:
                            transactions[transaction_id][self.KEY_T_FEE] = result["fee"]
                        if "comment" in result and result["comment"] != None and result["comment"] != "":
                            transactions[transaction_id][self.KEY_T_COMMENT] = result["comment"]
                        if "type" in result and result["type"] != None:
                            transactions[transaction_id][self.KEY_T_TYPE] = result["type"]
                except Exception as e:
                    self.log_exception(e, "Server - Wallet - Existing transaction")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

                # transactions_add - New transaction
                if self.KEY_T in account:
                    transaction_list = dict(sorted(account[self.KEY_T].items(), key=lambda item: item[1][self.KEY_T_INDEX]))
                    for transaction_id, transaction in transaction_list.items():
                        try:
                            result = self.transactions_add(
                                token=token,
                                account_id=account_id,
                                account_data=account[self.KEY_A_DATA] if self.KEY_A_DATA in account else None,
                                transaction_data=transaction[self.KEY_T_DATA]
                            )
                            transaction_id_new = result["transaction_id"] if "transaction_id" in result else transaction_id
                            transactions[transaction_id_new] = {
                                self.KEY_T_STATE: result["state"] if "state" in result else self.TRANSACTION_STATE_PROCESSING
                            }
                            if transaction_id_new != transaction_id:
                                transactions[transaction_id_new][self.KEY_T_ID] = transaction_id
                            if "data" in result and result["data"] != None and len(result["data"]) > 0:
                                transactions[transaction_id_new][self.KEY_T_DATA] = result["data"]
                            if "state_reason" in result:
                                transactions[transaction_id_new][self.KEY_T_STATE_REASON] = result["state_reason"]
                        except Exception as e:
                            self.log_exception(e, "Server - Wallet - New transaction")
                            transactions[transaction_id] = {
                                self.KEY_T_STATE: self.TRANSACTION_STATE_FAILED_TMP
                            }
                            data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

                if len(transactions) > 0:
                    data_return[self.KEY_A][account_id][self.KEY_T] = transactions

                # accounts_get - Existing account
                try:
                    result = self.accounts_get(token=token, account_id=account_id)
                    if "balance" in result:
                        data_return[self.KEY_A][account_id][self.KEY_A_BALANCE] = result["balance"]
                    if "nonce" in result:
                        data_return[self.KEY_A][account_id][self.KEY_A_NONCE] = result["nonce"]
                    if "delegate" in result:
                        data_return[self.KEY_A][account_id][self.KEY_A_DELEGATE] = result["delegate"]
                    if "vote" in result:
                        data_return[self.KEY_A][account_id][self.KEY_A_VOTE] = result["vote"]
                except Exception as e:
                    self.log_exception(e, "Server - Wallet - Existing account")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            if len(data_return[self.KEY_A]) == 0:
                del data_return[self.KEY_A]

        # delegates
        if self.KEY_D in data:
            data_return[self.KEY_D] = {}

            for delegate_token, delegate in data[self.KEY_D].items():
                token_connection = token_connection_response_start(token_connection=token_connection, token=delegate_token)

                # delegates_get - Existing delegate
                try:
                    delegates = {}
                    delegates_name = {}
                    delegates_value = {}

                    for delegate_id, result in self.delegates_get(token=delegate_token).items():
                        delegates[delegate_id] = {}
                        delegates_name[delegate_id] = {}
                        delegates_value[delegate_id] = {}
                        if "name" in result and result["name"] != None and result["name"] != "":
                            delegates[delegate_id][self.KEY_D_NAME] = result["name"]
                            delegates_name[delegate_id][self.KEY_D_NAME] = result["name"]
                        if "value" in result and result["value"] != None and result["value"] != 0:
                            delegates[delegate_id][self.KEY_D_VALUE] = result["value"]
                            delegates_value[delegate_id][self.KEY_D_VALUE] = result["value"]
                        if "data" in result and result["data"] != None and len(result["data"]) > 0:
                            delegates[delegate_id][self.KEY_D_DATA] = result["data"]
                        if "state" in result and result["state"] != None:
                            delegates[delegate_id][self.KEY_D_STATE] = result["state"]
                            delegates_value[delegate_id][self.KEY_D_STATE] = result["state"]

                    delegates_name_hash = RNS.Identity.full_hash(msgpack.packb(sorted(delegates_name.items())))
                    delegates_value_hash = RNS.Identity.full_hash(msgpack.packb(sorted(delegates_value.items())))
                    if delegate[self.KEY_D_NAME_HASH] != delegates_name_hash and delegate[self.KEY_D_VALUE_HASH] != delegates_value_hash:
                        pass
                    elif delegate[self.KEY_D_NAME_HASH] != delegates_name_hash:
                        delegates = delegates_name
                    elif delegate[self.KEY_D_VALUE_HASH] != delegates_value_hash:
                        delegates = delegates_value
                    else:
                        delegates = {}

                    if len(delegates) > 0:
                        data_return[self.KEY_D][delegate_token] = delegates
                except Exception as e:
                    self.log_exception(e, "Server - Wallet - Existing delegate")
                    data_return[self.KEY_RESULT] = self.RESULT_PARTIAL

            if len(data_return[self.KEY_D]) == 0:
                del data_return[self.KEY_D]

        token_connection_response_stop(token_connection=token_connection)

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    #################################################
    # Accounts                                      #
    #################################################


    def accounts_add(self, token, data):
        RNS.log("Server - Accounts - Add: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].accounts_add(token, data)


    def accounts_count(self, token, filter, search):
        RNS.log("Server - Accounts - Count: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].accounts_count(token, filter, search)


    def accounts_get(self, token, account_id):
        RNS.log("Server - Accounts - Get: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].accounts_get(token, account_id)


    def accounts_list(self, token, filter, search, order, limit, limit_start):
        RNS.log("Server - Accounts - List: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].accounts_list(token, filter, search, order, limit, limit_start)


    #################################################
    # API                                           #
    #################################################


    def api_delete(self, token, url, data, json, headers, cookies, auth, timeout):
        RNS.log("Server - API - Delete: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].api_delete(token, url, data, json, headers, cookies, auth, timeout)


    def api_get(self, token, url, data, json, headers, cookies, auth, timeout):
        RNS.log("Server - API - Get: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].api_get(token, url, data, json, headers, cookies, auth, timeout)


    def api_patch(self, token, url, data, json, headers, cookies, auth, timeout):
        RNS.log("Server - API - Patch: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].api_patch(token, url, data, json, headers, cookies, auth, timeout)


    def api_post(self, token, url, data, json, headers, cookies, auth, timeout):
        RNS.log("Server - API - Post: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].api_post(token, url, data, json, headers, cookies, auth, timeout)


    def api_put(self, token, url, data, json, headers, cookies, auth, timeout):
        RNS.log("Server - API - Put: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].api_put(token, url, data, json, headers, cookies, auth, timeout)


    #################################################
    # Blocks                                        #
    #################################################


    def blocks_count(self, token, filter, search):
        RNS.log("Server - Blocks - Count: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].blocks_count(token, filter, search)


    def blocks_list(self, token, filter, search, order, limit, limit_start):
        RNS.log("Server - Blocks - List: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].blocks_list(token, filter, search, order, limit, limit_start)


    #################################################
    # Connection                                    #
    #################################################


    def connection_response_start(self, token):
        RNS.log("Server - Connection - Start: "+str(token), RNS.LOG_EXTREME)
        try:
            self.token[self.token_map[token]].connection_response_start(token)
        except Exception as e:
            self.log_exception(e, "Server - Connection start")


    def connection_response_stop(self, token):
        RNS.log("Server - Connection - Stop: "+str(token), RNS.LOG_EXTREME)
        try:
            self.token[self.token_map[token]].connection_response_stop(token)
        except Exception as e:
            self.log_exception(e, "Server - Connection stop")


    #################################################
    # Delegates                                     #
    #################################################


    def delegates_count(self, token, filter, search):
        RNS.log("Server - Delegates - Count: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].delegates_count(token, filter, search)


    def delegates_get(self, token):
        RNS.log("Server - Delegates - Get: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].delegates_get(token)


    def delegates_list(self, token, filter, search, order, limit, limit_start):
        RNS.log("Server - Delegates - List: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].delegates_list(token, filter, search, order, limit, limit_start)


    #################################################
    # Infos                                         #
    #################################################


    def infos_count(self, token, filter, search):
        RNS.log("Server - Infos - Count: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].infos_count(token, filter, search)


    def infos_list(self, token, filter, search, order, limit, limit_start):
        RNS.log("Server - Infos - List: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].infos_list(token, filter, search, order, limit, limit_start)


    #################################################
    # Token                                         #
    #################################################


    def token_init(self):
        RNS.log("Server - Token - Init", RNS.LOG_DEBUG)

        self.token = {}
        self.token_map = {}

        for file in os.listdir(os.path.abspath(os.path.dirname(__file__))+"/blockchaintoken"):
            try:
                if file.startswith("__init__"):
                    continue
                elif file.endswith(".py"):
                    token_parent = file[:-3]
                elif file.endswith(".pyc"):
                    token_parent = file[:-4]
                else:
                    continue
                module = importlib.import_module(f".{token_parent}", package="blockchaintoken")
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isinstance(attribute, type):
                        self.token[token_parent] = attribute(self, token_parent)
                        for token_child in self.token[token_parent].token:
                            self.token_map[token_child] = token_parent
                        break
            except Exception as e:
                self.log_exception(e, "Server - Token - Init")

        RNS.log("Server - Token - Init: "+str(self.token_map), RNS.LOG_DEBUG)


    #################################################
    # Transactions                                  #
    #################################################


    def transactions_add(self, token, account_id, account_data, transaction_data):
        RNS.log("Server - Transactions - Add: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].transactions_add(token, account_id, account_data, transaction_data)


    def transactions_count(self, token, filter, search):
        RNS.log("Server - Transactions - Count: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].transactions_count(token, filter, search)


    def transactions_get(self, token, account_id, ts):
        RNS.log("Server - Transactions - Get: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].transactions_get(token, account_id, ts)


    def transactions_list(self, token, filter, search, order, limit, limit_start):
        RNS.log("Server - Transactions - List: "+str(token), RNS.LOG_DEBUG)
        return self.token[self.token_map[token]].transactions_list(token, filter, search, order, limit, limit_start)


    #################################################
    # Helpers                                       #
    #################################################


    def generate_id(self, length=32):
        characters = string.ascii_letters + string.digits
        result_str = "".join(random.choice(characters) for _ in range(length))
        return result_str




##############################################################################################################
# Config


#### Config - Get #####
def config_get(config, section, key, default="", lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section][key+lng_key]
    elif config.has_option(section, key):
        return config[section][key]
    return default


def config_getint(config, section, key, default=0, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config.getint(section, key+lng_key)
    elif config.has_option(section, key):
        return config.getint(section, key)
    return default


def config_getboolean(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section].getboolean(key+lng_key)
    elif config.has_option(section, key):
        return config[section].getboolean(key)
    return default


def config_getsection(config, section, default="", lng_key=""):
    if not config or section == "": return default
    if not config.has_section(section): return default
    if config.has_section(section+lng_key):
        return key+lng_key
    elif config.has_section(section):
        return key
    return default


def config_getoption(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return key+lng_key
    elif config.has_option(section, key):
        return key
    return default


#### Config - Read #####
def config_read(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    else:
        CONFIG = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        CONFIG.sections()
        if os.path.isfile(file):
            try:
                if file_override is None:
                    CONFIG.read(file, encoding='utf-8')
                elif os.path.isfile(file_override):
                    CONFIG.read([file, file_override], encoding='utf-8')
                else:
                    CONFIG.read(file, encoding='utf-8')
            except Exception as e:
                return False
        else:
            if not config_default(file=file, file_override=file_override):
                return False
    return True


#### Config - Save #####
def config_save(file=None):
    global CONFIG

    if file is None:
        return False
    else:
        if os.path.isfile(file):
            try:
                with open(file,"w") as file:
                    CONFIG.write(file)
            except Exception as e:
                return False
        else:
            return False
    return True


#### Config - Default #####
def config_default(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    elif DEFAULT_CONFIG != "":
        if file_override and DEFAULT_CONFIG_OVERRIDE != "":
            if not os.path.isdir(os.path.dirname(file_override)):
                try:
                    os.makedirs(os.path.dirname(file_override))
                except Exception:
                    return False
            if not os.path.exists(file_override):
                try:
                    config_file = open(file_override, "w")
                    config_file.write(DEFAULT_CONFIG_OVERRIDE)
                    config_file.close()
                except:
                    return False

        if not os.path.isdir(os.path.dirname(file)):
            try:
                os.makedirs(os.path.dirname(file))
            except Exception:
                return False
        try:
            config_file = open(file, "w")
            config_file.write(DEFAULT_CONFIG)
            config_file.close()
            if not config_read(file=file, file_override=file_override):
                return False
        except:
            return False
    else:
        return False

    if not CONFIG.has_section("main"): CONFIG.add_section("main")
    CONFIG["main"]["default_config"] = "True"
    return True


##############################################################################################################
# Log


LOG_FORCE    = -1
LOG_CRITICAL = 0
LOG_ERROR    = 1
LOG_WARNING  = 2
LOG_NOTICE   = 3
LOG_INFO     = 4
LOG_VERBOSE  = 5
LOG_DEBUG    = 6
LOG_EXTREME  = 7

LOG_LEVEL         = LOG_NOTICE
LOG_LEVEL_SERVICE = LOG_NOTICE
LOG_TIMEFMT       = "%Y-%m-%d %H:%M:%S"
LOG_MAXSIZE       = 5*1024*1024
LOG_PREFIX        = ""
LOG_SUFFIX        = ""
LOG_FILE          = ""


def log(text, level=3, file=None):
    if not LOG_LEVEL:
        return

    if LOG_LEVEL >= level:
        name = "Unknown"
        if (level == LOG_FORCE):
            name = ""
        if (level == LOG_CRITICAL):
            name = "Critical"
        if (level == LOG_ERROR):
            name = "Error"
        if (level == LOG_WARNING):
            name = "Warning"
        if (level == LOG_NOTICE):
            name = "Notice"
        if (level == LOG_INFO):
            name = "Info"
        if (level == LOG_VERBOSE):
            name = "Verbose"
        if (level == LOG_DEBUG):
            name = "Debug"
        if (level == LOG_EXTREME):
            name = "Extra"

        if not isinstance(text, str):
            text = str(text)

        text = "[" + time.strftime(LOG_TIMEFMT, time.localtime(time.time())) +"] [" + name + "] " + LOG_PREFIX + text + LOG_SUFFIX

        if file == None and LOG_FILE != "":
            file = LOG_FILE

        if file == None:
            print(text)
        else:
            try:
                file_handle = open(file, "a")
                file_handle.write(text + "\n")
                file_handle.close()
                
                if os.path.getsize(file) > LOG_MAXSIZE:
                    file_prev = file + ".1"
                    if os.path.isfile(file_prev):
                        os.unlink(file_prev)
                    os.rename(file, file_prev)
            except:
                return


def log_exception(e, text="", level=1):
    import traceback

    log(text+" - An "+str(type(e))+" occurred: "+str(e), level)
    log("".join(traceback.TracebackException.from_exception(e).format()), level)


##############################################################################################################
# System


#### Panic #####
def panic():
    sys.exit(255)


#### Exit #####
def exit():
    sys.exit(0)


##############################################################################################################
# Setup/Start


#### Setup #####
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
    global RNS_CONNECTION
    global RNS_SERVER_BLOCKCHAIN

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    if path_rns is not None:
        if path_rns.endswith("/"):
            path_rns = path_rns[:-1]
        PATH_RNS = path_rns

    if loglevel is not None:
        LOG_LEVEL = loglevel
        rns_loglevel = loglevel
    else:
        rns_loglevel = None

    if service:
        LOG_LEVEL = LOG_LEVEL_SERVICE
        if path_log is not None:
            if path_log.endswith("/"):
                path_log = path_log[:-1]
            LOG_FILE = path_log
        else:
            LOG_FILE = PATH
        LOG_FILE = LOG_FILE + "/" + NAME + ".log"
        rns_loglevel = None

    if not config_read(PATH + "/config.cfg", PATH + "/config.cfg.owr"):
        print("Config - Error reading config file " + PATH + "/config.cfg")
        panic()

    if CONFIG["main"].getboolean("default_config"):
        print("Exit!")
        print("First start with the default config!")
        print("You should probably edit the config file \"" + PATH + "/config.cfg\" to suit your needs and use-case!")
        print("You should make all your changes at the user configuration file \"" + PATH + "/config.cfg.owr\" to override the default configuration file!")
        print("Then restart this program again!")
        exit()

    if not CONFIG["main"].getboolean("enabled"):
        print("Disabled in config file. Exit!")
        exit()

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
    log("   Data File: " + PATH + "/data.cfg", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("RNS - Connecting ...", LOG_DEBUG)

    if path is None:
        path = PATH

    announce_data = CONFIG["rns_server"]["display_name"]
    if CONFIG["main"].getboolean("fields_announce"):
        fields = {}
        if CONFIG["telemetry"].getboolean("location_enabled"):
            try:
               fields[MSG_FIELD_LOCATION] = [CONFIG["telemetry"].getfloat("location_lat"), CONFIG["telemetry"].getfloat("location_lon")]
            except:
                pass
        if CONFIG["telemetry"].getboolean("owner_enabled"):
            try:
               fields[MSG_FIELD_OWNER] = bytes.fromhex(CONFIG["telemetry"]["owner_data"])
            except:
                pass
        if CONFIG["telemetry"].getboolean("state_enabled"):
            try:
               fields[MSG_FIELD_STATE] = [CONFIG["telemetry"].getint("state_data"), int(time.time())]
            except:
                pass
        if len(fields) > 0:
            announce_data = [CONFIG["rns_server"]["display_name"].encode("utf-8"), None, fields]
            log("RNS - Configured announce data: "+str(announce_data), LOG_DEBUG)
            announce_data = msgpack.packb(announce_data)

    RNS_SERVER_BLOCKCHAIN = ServerBlockchain(
        storage_path=path,

        identity_file="identity",
        identity=None,

        ratchets=CONFIG["rns_server"].getboolean("destination_ratchets"),

        destination_name=CONFIG["rns_server"]["destination_name"],
        destination_type=CONFIG["rns_server"]["destination_type"],

        announce_startup=CONFIG["rns_server"].getboolean("announce_startup"),
        announce_startup_delay=CONFIG["rns_server"]["announce_startup_delay"],
        announce_periodic=CONFIG["rns_server"].getboolean("announce_periodic"),
        announce_periodic_interval=CONFIG["rns_server"]["announce_periodic_interval"],
        announce_data=announce_data,
        announce_hidden=CONFIG["rns_server"].getboolean("announce_hidden"),

        limiter_server_enabled=CONFIG["rns_server"].getboolean("limiter_server_enabled"),
        limiter_server_calls=CONFIG["rns_server"]["limiter_server_calls"],
        limiter_server_size=CONFIG["rns_server"]["limiter_server_size"],
        limiter_server_duration=CONFIG["rns_server"]["limiter_server_duration"],

        limiter_peer_enabled=CONFIG["rns_server"].getboolean("limiter_peer_enabled"),
        limiter_peer_calls=CONFIG["rns_server"]["limiter_peer_calls"],
        limiter_peer_size=CONFIG["rns_server"]["limiter_peer_size"],
        limiter_peer_duration=CONFIG["rns_server"]["limiter_peer_duration"],

        limiter_api_enabled=CONFIG["rns_server"].getboolean("limiter_api_enabled"),
        limiter_api_calls=CONFIG["rns_server"]["limiter_api_calls"],
        limiter_api_size=CONFIG["rns_server"]["limiter_api_size"],
        limiter_api_duration=CONFIG["rns_server"]["limiter_api_duration"],

        limiter_explorer_enabled=CONFIG["rns_server"].getboolean("limiter_explorer_enabled"),
        limiter_explorer_calls=CONFIG["rns_server"]["limiter_explorer_calls"],
        limiter_explorer_size=CONFIG["rns_server"]["limiter_explorer_size"],
        limiter_explorer_duration=CONFIG["rns_server"]["limiter_explorer_duration"],

        limiter_wallet_enabled=CONFIG["rns_server"].getboolean("limiter_wallet_enabled"),
        limiter_wallet_calls=CONFIG["rns_server"]["limiter_wallet_calls"],
        limiter_wallet_size=CONFIG["rns_server"]["limiter_wallet_size"],
        limiter_wallet_duration=CONFIG["rns_server"]["limiter_wallet_duration"],
    )

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_BLOCKCHAIN.destination_hash()), LOG_FORCE)
    log("...............................................................................", LOG_FORCE)

    while True:
        time.sleep(1)


#### Start ####
def main():
    try:
        description = NAME + " - " + DESCRIPTION
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument("-p", "--path", action="store", type=str, default=None, help="Path to alternative config directory")
        parser.add_argument("-pr", "--path_rns", action="store", type=str, default=None, help="Path to alternative Reticulum config directory")
        parser.add_argument("-pl", "--path_log", action="store", type=str, default=None, help="Path to alternative log directory")
        parser.add_argument("-l", "--loglevel", action="store", type=int, default=LOG_LEVEL)
        parser.add_argument("-s", "--service", action="store_true", default=False, help="Running as a service and should log to file")
        parser.add_argument("--exampleconfig", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")
        parser.add_argument("--exampleconfigoverride", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")

        params = parser.parse_args()

        if params.exampleconfig:
            print("Config File: " + PATH + "/config.cfg")
            print("Content:")
            print(DEFAULT_CONFIG)
            exit()

        if params.exampleconfigoverride:
            print("Config Override File: " + PATH + "/config.cfg.owr")
            print("Content:")
            print(DEFAULT_CONFIG_OVERRIDE)
            exit()

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Files


#### Default configuration override file ####
DEFAULT_CONFIG_OVERRIDE = '''# This is the user configuration file to override the default configuration file.
# All settings made here have precedence.
# This file can be used to clearly summarize all settings that deviate from the default.
# This also has the advantage that all changed settings can be kept when updating the program.


[rns_server]
display_name = Server

announce_startup = Yes
announce_startup_delay = 0 #Seconds

announce_periodic = Yes
announce_periodic_interval = 120 #Minutes


[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

owner_enabled = False
owner_data = 

state_enabled = False
state_data = 0
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True

# Name of the program. Only for display in the log or program startup.
name = RNS Server Blockchain

# Transport extended data in the announce.
# This is needed for the integration of advanced client apps.
fields_announce = True


#### RNS server settings ####
[rns_server]

# Enable ratchets for the destination
destination_ratchets = No

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = nomadnetwork
destination_type = bc

# The name will be visible to other peers
# on the network, and included in announces.
display_name = Server

# The server is announced at startup
# to let clients reach it immediately.
announce_startup = Yes
announce_startup_delay = 0 #Seconds

# The server is announced periodically
# to let clients reach it.
announce_periodic = Yes
announce_periodic_interval = 120 #Minutes

# The announce is hidden for client applications
# but is still used for the routing tables.
announce_hidden = No

# Limits the number of simultaneous requests/calls per server.
limiter_server_enabled = No
limiter_server_calls = 1000 # Number of calls per duration. 0=Any
limiter_server_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_server_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_peer_enabled = Yes
limiter_peer_calls = 30 # Number of calls per duration. 0=Any
limiter_peer_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_peer_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_api_enabled = No
limiter_api_calls = 30 # Number of calls per duration. 0=Any
limiter_api_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_api_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_explorer_enabled = No
limiter_explorer_calls = 30 # Number of calls per duration. 0=Any
limiter_explorer_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_explorer_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_wallet_enabled = No
limiter_wallet_calls = 30 # Number of calls per duration. 0=Any
limiter_wallet_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_wallet_duration = 60 # Seconds


#### Telemetry settings ####
[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

owner_enabled = False
owner_data = 

state_enabled = False
state_data = 0
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()
