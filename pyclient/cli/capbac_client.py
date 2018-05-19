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
from base64 import b64encode
import time
import getpass
import requests
import yaml
import os
import cbor

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

from cli.capbac_exceptions import CapBACException

# The Transaction Family Name
FAMILY_NAME='capbac'
FAMILY_VERSION='1.0'

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

class CapBACClient:
    def __init__(self, baseUrl, keyFile=None):

        self._baseUrl = baseUrl

        if keyFile is None:
            self._signer = None
            return

        try:
            with open(keyFile) as fd:
                privateKeyStr = fd.read().strip()
        except OSError as err:
            raise CapBACException(
                'Failed to read private key {}: {}'.format( \
                    keyFile, str(err)))

        try:
            privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
        except ParseError as e:
            raise CapBACException( \
                'Failed to load private key: {}'.format(str(e)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)

        self._publicKey = self._signer.get_public_key().as_hex()

        self._address = _sha512(FAMILY_NAME.encode('utf-8'))[0:6] + \
            _sha512(self._publicKey.encode('utf-8'))[0:64]

    # For each valid cli commands in _cli.py file
    # Add methods to:
    # 1. Do any additional handling, if required
    # 2. Create a transaction and a batch
    # 2. Send to rest-api
    def issue(self, capability):

        capability['IS'] = str(self._signer.get_public_key().as_hex())

        # Generate the CBOR encoded payload
        payload = cbor.dumps({
            'AC': "issue",
            'CT': capability
        })

        identifier = capability['ID']

        return self._send_transaction(payload, [identifier], [identifier])

    def _send_request(self,
                      suffix,
                      data=None,
                      contentType=None):
        if self._baseUrl.startswith("http://"):
            url = "{}/{}".format(self._baseUrl, suffix)
        else:
            url = "http://{}/{}".format(self._baseUrl, suffix)

        headers = {}

        if contentType is not None:
            headers['Content-Type'] = contentType

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise CapBACException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise CapBACException(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise CapBACException(err)

        return result.text

    def _get_prefix(self):
        return _sha512('capbac'.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

    def _get_pubkeyfile(self):
        real_user = getpass.getuser()
        home = os.path.expanduser("~")
        key_dir = os.path.join(home, ".sawtooth", "keys")
        return '{}/{}.pub'.format(key_dir, real_user)

    def _send_transaction(self, payload, input_ids, output_ids):

        # Construct the addresses
        input_addresses = []
        for identifier in input_ids:
            input_addresses.append(self._get_address(identifier))

        output_addresses = []
        for identifier in output_ids:
            output_addresses.append(self._get_address(identifier))

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name=FAMILY_NAME,
            family_version=FAMILY_VERSION,
            inputs=input_addresses,
            outputs=output_addresses,
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
            'application/octet-stream',
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
