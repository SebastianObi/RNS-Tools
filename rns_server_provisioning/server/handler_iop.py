##############################################################################################################
# Include


#### System ####
import rsa, json, iop_python as iop

#### Internal ####
from utils.utils import response_create, RESPONSE_CODES as resp


##############################################################################################################
# HandlerIOP Class


class HandlerIOP:
    def __init__(self, owner):
        self.owner = owner

        if "limiter_enabled" in self.owner.config["handler_iop"] and  self.owner.config["handler_iop"].getboolean("limiter_enabled"):
            self.limiter = RateLimiter(int(self.owner.config["handler_iop"]["limiter_calls"]), int(self.owner.config["handler_iop"]["limiter_size"]), int(self.owner.config["handler_iop"]["limiter_duration"]))
        else:
            self.limiter = None

        root = self.owner.config["handler_iop"]["root"]

        self.owner.register_request_handler(
            path=root+"phrase",
            response_generator=self.get_phrase_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"get_hyd_vault",
            response_generator=self.get_hyd_vault_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"phrase",
            response_generator=self.get_phrase_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"get_hyd_vault",
            response_generator=self.get_hyd_vault_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"get_morpheus_vault",
            response_generator=self.get_morpheus_vault_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"get_new_acc_on_vault",
            response_generator=self.get_new_account_on_vault_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"get_wallet",
            response_generator=self.get_wallet_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"generate_did_by_morpheus",
            response_generator=self.generate_did_by_morpheus_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"sign_witness_statement",
            response_generator=self.sign_witness_statement_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"sign_did_statement",
            response_generator=self.sign_did_statement_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"nonce",
            response_generator=self.get_nonce_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )
        self.owner.register_request_handler(
            path=root+"sign_transaction",
            response_generator=self.sign_transaction_handler,
            limiter=self.limiter,
            limiter_type=self.owner.LIMITER_TYPE_JSON
        )


    def get_phrase_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            phrase = iop.generate_phrase()
            response_data = {"phrase": phrase}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def get_hyd_vault_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            phrase = data['phrase']

            hyd_vault = iop.get_hyd_vault(phrase, password)

            response_data = {
                "hyd_vault": hyd_vault
            }

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def get_morpheus_vault_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            phrase = data['phrase']

            morpheus_vault = iop.get_morpheus_vault(phrase, password)
            response_data = {"morpheus_vault": morpheus_vault}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def get_new_account_on_vault_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            vault = data['vault']
            account = data['account']

            new_vault = iop.get_new_acc_on_vault(vault, password.decode("utf8"), int(account))
            response_data = {"vault": new_vault}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def get_wallet_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            vault = data['vault']
            account = data['account']

            address = iop.get_wallet(vault, int(account))
            response_data = {'address':address}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def generate_did_by_morpheus_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            vault = data['vault']

            did = iop.generate_did_by_morpheus(vault, password)
            response_data = {"did": did}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def sign_witness_statement_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            vault = data['vault']
            statement_data = data['data']

            signed_statement = iop.sign_witness_statement(vault, password, statement_data)
            response_data = {"signed": signed_statement}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def sign_did_statement_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            vault = data['vault']
            data_hex = data['data']
            statement_data = bytes.fromhex(data_hex)

            signature, public_key = iop.sign_did_statement(vault, password, statement_data)
            response_data = {"signature": signature, "public_key": public_key}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def get_nonce_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            nonce = iop.generate_nonce()
            response_data = {'nonce':nonce}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')


    def sign_transaction_handler(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return response_create('0x01', resp.get('0x01'), "Invalid Data")

            password = data['password']
            vault = data['vault']
            salt = data['salt']
            receiver = data['receiver']
            amount = data['amount']
            nonce = data['nonce']
            hash_received = data['hash']
            account = data['account']

            message = receiver + amount + nonce + account + salt + password
            computed_hash = rsa.compute_hash(message.encode(), 'SHA-1')

            if computed_hash != hash_received:
                return response_create('400', '400', 'Invalid hash')

            signed_transaction = iop.generate_transaction(vault, receiver, amount, nonce, password, account)
            response_data = {'transaction': signed_transaction}

            return response_create('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return response_create('500', '500', f'Error: {str(e)}')
