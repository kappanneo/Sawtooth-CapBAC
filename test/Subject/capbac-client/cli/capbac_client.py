# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import hashlib
import base64
import time
import requests
import yaml
import json
import cbor
import logging #debug

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

from cli.capbac_exceptions import CapBACClientException
from cli.capbac_version import *

LOGGER = logging.getLogger(__name__)

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _check_format(dictionary,name,dictionary_format,subset=None):
    if subset is None:
        subset = set(dictionary_format)
    for label in subset:
        if label not in dictionary:
            raise CapBACClientException("Invalid {}: {} missing ({})"
            .format(name,label,dictionary_format[label]['description']))
        feature = dictionary[label]
        if 'allowed values' in dictionary_format[label]:
            if feature not in dictionary_format[label]['allowed values']:
                raise CapBACClientException(
                "Invalid {}: {} value should be one the following: {}"
                .format(name,label,dictionary_format[label]['allowed values']))
        elif 'allowed types' in dictionary_format[label]:
            if type(feature) not in dictionary_format[label]['allowed types']:
                raise CapBACClientException(
                "Invalid {}: {} type not allowed".format(name,label))
        elif type(feature) == str: # string allowed by default
            if 'len' in dictionary_format[label]:
                if len(feature) != dictionary_format[label]['len']:
                    raise CapBACClientException(
                        "Invalid {}: {} length should be {}"
                        .format(name,label,dictionary_format[label]['len']))
            elif 'max_len' in dictionary_format[label]:
                if len(feature) > dictionary_format[label]['max_len']:
                    raise CapBACClientException(
                        "Invalid {}: {} length should less than {}"
                        .format(name,label,dictionary_format[label]['max_len']))
        else:
            raise CapBACClientException(
                "Invalid {}: {} should be a string".format(name,label))
    for label in dictionary:
        if label not in subset:
            raise CapBACClientException("Invalid {}: unexpected label {}".format(name,label))

class CapBACClient:
    def __init__(self, url, keyfile=None):
        self.url = url

        if keyfile is not None:
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise CapBACClientException(
                    'Failed to read private key: {}'.format(str(err)))

            try:
                private_key = Secp256k1PrivateKey.from_hex(private_key_str)
            except ParseError as e:
                raise CapBACClientException(
                    'Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(
                create_context('secp256k1')).new_signer(private_key)

    # For each valid cli commands in _cli.py file
    # Add methods to:
    # 1. Do any additional handling, if required
    # 2. Create a transaction and a batch
    # 2. Send to rest-api

    def issue(self, token, is_root):

        try:
            token = json.loads(token)
        except:
            raise CapBACClientException('Invalid token: serialization failed')

        return self.issue_from_dict(token, is_root)

    def issue_from_dict(self,token, is_root):

        # check the formal validity of the incomplete token
        subset = set(CAPABILITY_FORMAT) - {'II','SI','VR'}
        if is_root: subset -= {'IC','SU'}

        _check_format(token,'capabiliy token',CAPABILITY_FORMAT,subset)

        for access_right in token['AR']:
            _check_format(access_right,'capability token: access right',ACCESS_RIGHT_FORMAT)

        # time interval logical check
        try:
            not_before = int(token['NB'])
            not_after  = int(token['NA'])
        except:
            raise CapBACClientException('Invalid capability: timestamp not a number')

        if not_before > not_after:
            raise CapBACClientException("Invalid capability: incorrect time interval")

        now = int(time.time())
        if now > not_after:
            raise CapBACClientException("Capability already expired")

        if is_root:
            token['IC'] = None
            token['SU'] = self._signer.get_public_key().as_hex()

        # add signature
        token= self.sign_dict(token)

        # now the token is complete

        payload = cbor.dumps({
            'AC': "issue",
            'OB': token
        })

        return self._send_transaction(payload, token['DE'])

    def revoke(self, token):

        try:
            token = json.loads(token)
        except:
            raise CapBACClientException('Invalid revocation token: serialization failed')

        return self.revoke_from_dict(token)

    def revoke_from_dict(self, token):

        # check the formal validity of the incomplete revocation token
        subset = set(REVOCATION_FORMAT) - {'II','SI','VR'}

        _check_format(token,'revocation token',REVOCATION_FORMAT,subset)

        # add signature
        token = self.sign_dict(token)

        # now the revocation token is complete

        payload = cbor.dumps({
            'AC': "revoke",
            'OB': token
        })

        return self._send_transaction(payload, token['DE'])

    def list(self,device):

        if len(device) > MAX_URI_LENGTH:
            raise CapBACClientException(
                'Invalid URI: max length exceeded, should be less than {}'
                .format(MAX_URI_LENGTH))

        result = self._send_request(
            "state?address={}".format(
                self._get_address(device)))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            data_list = [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

            return json.dumps({
                x:y[x] for y in data_list for x in y
            }, indent=4, sort_keys=True)

        except BaseException:
            return None

    def validate(self,token):

        try:
            token = json.loads(token)
        except:
            raise CapBACClientException('Invalid access token: serialization failed')

        return self.validate_from_dict(token)

    def validate_from_dict(self,token):

        _check_format(token,"access token",VALIDATION_FORMAT)

        # state retrival
        device = token['DE']
        result = self._send_request(
            "state?address={}".format(
                self._get_address(device)))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            data_list =  [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

            state = {x:y[x] for y in data_list for x in y}

        except BaseException:
            return None

        LOGGER.info('checking authorization')
        # check authorization
        capability = token['IC']

        if capability not in state:
            return False

        LOGGER.info('checking delegation chain')
        # delegation chain check
        now = int(time.time())
        resource = token['RE']
        action = token['AC']

        current_token = state[capability]
        parent = current_token['IC']
        while parent != None:
            if parent not in state:
                raise BaseException
            parent_token = state[parent]

            # check time interval
            if now >= int(parent_token['NA']):
                return False
            if now < int(parent_token['NB']):
                return False

            # check access rights
            if resource not in parent_token["AR"]:
                return False
            if action not in parent_token["AR"][resource]:
                return False

            # next
            current_token = parent_token
            parent = current_token['IC']

        LOGGER.info('checking signature')
        # check signature
        signature = token.pop('SI')
        if not create_context('secp256k1').verify(
            signature,
            str(cbor.dumps(token,sort_keys=True)).encode('utf-8'),
            Secp256k1PublicKey.from_hex(state[capability]['SU'])
            ):
            return False

        return True

    def sign(self, token):

        try:
            token = json.loads(token)
        except:
            raise CapBACClientException('Invalid token: serialization failed')

        token = self.sign_dict(token)
        return json.dumps(token)

    def sign_dict(self, token):

        # add version
        token['VR'] = FAMILY_VERSION

        # add issue time
        now = int(time.time())
        token['II'] = str(now)

        # add signature
        token_serialized = str(cbor.dumps(token,sort_keys=True)).encode('utf-8')
        token['SI'] = self._signer.sign(token_serialized)

        return token

    def _get_prefix(self):
        return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

    def _get_address(self, device):
        prefix = self._get_prefix()
        device_address = _sha512(device.encode('utf-8'))[64:]
        return prefix + device_address

    def _send_request(self,
                      suffix,
                      data=None,
                      contentType=None):
        if self.url.startswith("http://"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "http://{}/{}".format(self.url, suffix)

        headers = {}

        if contentType is not None:
            headers['Content-Type'] = contentType

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise CapBACClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise CapBACClientException(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise CapBACClientException(err)

        return result.text

    def _send_transaction(self, payload, device):

        # Get the unique address for the device's tokens
        address = self._get_address(device)

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=FAMILY_NAME,
            family_version=FAMILY_VERSION,
            inputs=[address],
            outputs=[address],
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=time.time().hex().encode()
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream'
        )

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)
        return BatchList(batches=[batch])
