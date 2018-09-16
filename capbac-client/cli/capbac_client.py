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

        # check the formal validity of the incomplete token
        subset = set(TOKEN_FORMAT) - {'II','SI','VR'}
        if is_root: subset -= {'IC','SU'}

        _check_format(token,'token',TOKEN_FORMAT,subset)

        for access_right in token['AR']:
            _check_format(access_right,'token: access right',ACCESS_RIGHT_FORMAT)

        # time interval logical check
        try:
            not_before = int(token['NB'])
            not_after  = int(token['NA'])
        except:
            raise CapBACClientException('Invalid token: timestamp not a number')

        if not_before > not_after:
            raise CapBACClientException("Invalid token: incorrect time interval")

        # add version
        token['VR'] = FAMILY_VERSION

        # add issue time
        now = int(time.time())
        if now > not_after:
            raise CapBACClientException("token already expired")
        token['II'] = str(now)

        if is_root:
            token['IC'] = None
            token['SU'] = self._signer.get_public_key().as_hex()

        # add signature
        cap_string = str(cbor.dumps(token,sort_keys=True)).encode('utf-8')
        token['SI'] = self._signer.sign(cap_string)

        # now the token is complete

        payload = cbor.dumps({
            'AC': "issue",
            'OB': token
        })

        return self._send_transaction(payload, token['DE'])

    def revoke(self, revocation):

        try:
            revocation = json.loads(revocation)
        except:
            raise CapBACClientException('Invalid revocation: serialization failed')

        # check the formal validity of the incomplete revocation
        subset = set(REVOCATION_FORMAT) - {'II','SI','VR'}

        _check_format(revocation,'revocation',REVOCATION_FORMAT,subset)

        # add version
        revocation['VR'] = FAMILY_VERSION

        # add issue time
        now = int(time.time())
        revocation['II'] = str(now)

        # add signature
        cap_string = str(cbor.dumps(revocation,sort_keys=True)).encode('utf-8')
        revocation['SI'] = self._signer.sign(cap_string)

        # now the revocation request is complete

        payload = cbor.dumps({
            'AC': "revoke",
            'OB': revocation
        })

        return self._send_transaction(payload, revocation['DE'])

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

    def validate(self,request):

        try:
            request = json.loads(request)
        except:
            raise CapBACClientException('Invalid request: serialization failed')

        _check_format(request,"request",VALIDATION_FORMAT)

        # state retrival
        device = request['DE']
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
        capability = request['IC']

        if capability not in state:
            return False

        LOGGER.info('checking delegation chain')
        # delegation chain check
        now = int(time.time())
        resource = request['RE']
        action = request['AC']

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
        signature = request.pop('SI')
        if not create_context('secp256k1').verify(
            signature,
            str(cbor.dumps(request,sort_keys=True)).encode('utf-8'),
            Secp256k1PublicKey.from_hex(state[capability]['SU'])
            ):
            return False

        return True

    def submit(self, request):

        try:
            request = json.loads(request)
        except:
            raise CapBACClientException('Invalid request: serialization failed')

        # check the formal validity of the incomplete access request
        subset = set(VALIDATION_FORMAT) - {'II','SI','VR'}

        _check_format(request,'request',VALIDATION_FORMAT,subset)

        # add version
        request['VR'] = FAMILY_VERSION

        # add issue time
        now = int(time.time())
        request['II'] = str(now)

        # add signature
        req_string = str(cbor.dumps(request,sort_keys=True)).encode('utf-8')
        request['SI'] = self._signer.sign(req_string)

        return json.dumps(request)

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
