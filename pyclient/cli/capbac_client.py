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
import cbor

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

from cli.capbac_exceptions import CapBACClientException

# The Transaction Family Name
FAMILY_NAME='capbac'
FAMILY_VERSION='1.0'

IDENTIFIER_LENGTH = 4

TIMESTAMP_LENGTH = 10

MAX_URI_LENGTH = 2000

TOKEN_FORMAT = {
    'ID': {
        'description': 'token identifier',
        'len': IDENTIFIER_LENGTH
    },
    'II': {
        'description': 'issue istant',
        'len': TIMESTAMP_LENGTH
    },
    'IS': {
        'description': 'issuer\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'SU': {
        'description': 'subject\'s public key',
        'len': 64
    },
    'DE': {
        'description': 'device\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'SI': {
        'description': 'issuer\'s signature',
        'len': 64
    },
    'PA': {
        'description': 'identifier of the parent token',
        'len': IDENTIFIER_LENGTH
    },
    'NB': {
        'description': 'not before time',
        'len': TIMESTAMP_LENGTH
    },
    'NA': {
        'description': 'not after time',
        'len': TIMESTAMP_LENGTH
    }
}


def _sha512(data):
    return hashlib.sha512(data).hexdigest()

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

    def issue(self, capability):

        try:
            capability = cbor.loads(capability)
        except:
            raise CapBACClientException('Invalid capability: serialization failed')

        # check the formal validity of the incomplete token
        subset = set(TOKEN_FORMAT) - {'II','IS'}
        for label in subset:
            if label not in capability:
                raise CapBACClientException("Invalid capability: {} missing ({})".format(label,TOKEN_FORMAT[label]['description']))
            feature = capability[label]
            if type(feature) != str:
                raise CapBACClientException("Invalid capability: {} should be a string".format(label))
            if 'len' in TOKEN_FORMAT[label]:
                if len(feature) != TOKEN_FORMAT[label]['len']:
                    raise CapBACClientException("Invalid capability: {} length should be {}".format(label,TOKEN_FORMAT[label]['len']))
            elif 'max_len' in TOKEN_FORMAT[label]:
                if len(feature) > TOKEN_FORMAT[label]['max_len']:
                    raise CapBACClientException("Invalid capability: {} length should less than {}".format(label,TOKEN_FORMAT[label]['max_len']))
        for label in capability:
            if label not in subset:
                raise CapBACClientException("Invalid capability: unexpected label {}".format(label))

        # time interval logical check
        not_before = int(capability['NB'])
        not_after = int(capability['NA'])
        if not_before > not_after:
            raise CapBACClientException("Invalid capability: incorrect time interval")

        # add issue time
        now = int(time.time())
        if now > not_after:
            raise CapBACClientException("Capability already expired")
        capability['II'] = str(now)

        # add signature
        capability['SI'] = self._signer.sign(str(capability))

        # now the token is complete

        payload = cbor.dumps({
            'AC': "issue",
            'CT': capability
        })

        return self._send_transaction(payload, capability['DE'])

    def revoke(self, capability, request):

        try:
            capability = cbor.loads(capability)
        except:
            raise CapBACClientException('Invalid capability: serialization failed')
        try:
            revocation = cbor.loads(request)
        except:
            raise CapBACClientException('Invalid request: serialization failed')

        payload = cbor.dumps({
            'AC': "revoke",
            'CT': capability,
            'RR': revocation
        })

        return self._send_transaction(payload,capability['DE'])

    def validate(self, capability, request):

        try:
            capability = cbor.loads(capability)
        except:
            raise CapBACClientException('Invalid capability: serialization failed')
        try:
            request = cbor.loads(request)
        except:
            raise CapBACClientException('Invalid request: serialization failed')

        result = self._send_request(
            "state?address={}".format(
                self._get_prefix()))

        # check

        return False

    def list(self,device):
        result = self._send_request(
            "state?address={}".format(
                self._get_prefix()))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

        except BaseException:
            return None

    def _get_prefix(self):
        return _sha512('intkey'.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

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
