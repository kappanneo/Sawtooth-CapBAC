# Copyright 2016 Intel Corporation
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

import sys
import argparse

import logging
import hashlib

import cbor
import time

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging
from sawtooth_sdk.processor.log import log_configuration
from sawtooth_sdk.processor.config import get_log_config
from sawtooth_sdk.processor.config import get_log_dir

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = 'capbac'
FAMILY_VERSION = '1.0'
IDENTIFIER_LENGTH = 16
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
        'len': 66
    },
    'DE': {
        'description': 'device\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'SI': {
        'description': 'issuer\'s signature',
        'len': 128
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

VALID_ACTIONS = 'issue', 'revoke', 'validate'
VALIDATOR_DEFAULT_URL = 'tcp://validator:4004'

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

def _get_prefix():
    return _sha512(FAMILY_NAME.encode('utf-8'))[0:6]

def _get_address(device):
    prefix = _get_prefix()
    device_address = _sha512(device.encode('utf-8'))[64:]
    return prefix + device_address

class CapBACTransactionHandler(TransactionHandler):
    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return [FAMILY_VERSION]

    @property
    def namespaces(self):
        return [_get_prefix()]

    def apply(self, transaction, context):
        action, capability, request, device = _unpack_transaction(transaction)

        state = _get_state_data(device, context)

        updated = _do_capbac(action, capability, request, device, state)

        _set_state_data(device, updated, context)

def _unpack_transaction(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')

    try:
        action = content['AC']
    except AttributeError:
        raise InvalidTransaction('Action is required as "AC" ')

    _validate_action(action)

    try:
        capability = content['CT']
    except AttributeError:
        raise InvalidTransaction('Capability token is required as "CT" ')

    _validate_capability(capability)

    device = capability['DE']

    if action == 'revoke':
        try:
            revocation = content['RR']
        except AttributeError:
            raise InvalidTransaction('For action "revoke" revocation request is required as "RE" ')

        _validate_request(content['RE'])

    else:
        revocation = None

    return action, capability, revocation, device


def _validate_action(action):
    if action not in VALID_ACTIONS:
        raise InvalidTransaction('Action must be one of: {}'.format(str(VALID_ACTIONS)))

def _validate_capability(capability):

    # check the formal validity of the complete token
    for label in TOKEN_FORMAT:
        if label not in capability:
            raise InvalidTransaction("Invalid capability: {} missing ({})".format(label,TOKEN_FORMAT[label]['description']))
        feature = capability[label]
        if not isinstance(feature, str):
            raise InvalidTransaction("Invalid capability: {} should be a string".format(label))
        if 'len' in TOKEN_FORMAT[label]:
            if len(feature) != TOKEN_FORMAT[label]['len']:
                raise InvalidTransaction("Invalid capability: {} length should be {} but is {}".format(label,TOKEN_FORMAT[label]['len'],len(feature)))
        elif 'max_len' in TOKEN_FORMAT[label]:
            if len(feature) > TOKEN_FORMAT[label]['max_len']:
                raise InvalidTransaction("Invalid capability: {} length should less than {} but is {}".format(label,TOKEN_FORMAT[label]['max_len'],len(feature)))
    for label in capability:
        if label not in TOKEN_FORMAT:
            raise InvalidTransaction("Invalid capability: unexpected label {}".format(label))

    # time interval logical check
    not_before = int(capability['NB'])
    not_after = int(capability['NA'])
    if not_before > not_after:
        raise InvalidTransaction("Invalid capability: incorrect time interval")

    # add issue time
    now = int(time.time())
    if now > not_after:
        raise InvalidTransaction("Invalid capability: capability expired")


def _validate_request(request):
    return

def _get_state_data(device, context):
    address = _get_address(device)

    state_entries = context.get_state([address])

    try:
        return cbor.loads(state_entries[0].data)
    except IndexError:
        return {}
    except:
        raise InternalError('Failed to load state data')


def _set_state_data(device, state, context):
    address = _get_address(device)

    encoded = cbor.dumps(state)

    addresses = context.set_state({address: encoded})

    if not addresses:
        raise InternalError('State error')


def _do_capbac(action, capability, request, device, state):

    if action == 'issue':
        return _do_issue(capability,state)
    if action == 'revoke':
        return _do_revoke(capability,request,state)
    if action == 'validate':
        return _do_validate(capability,request,state)

def _do_issue(capability, state):
    identifier = capability['ID']
    msg = 'Issuing capbabiltity token with ID: {}'.format(identifier)
    LOGGER.debug(msg)

    if identifier in state:
        raise InvalidTransaction(
            'Cannot issue: capability token with ID = {} already exists'.format(identifier)
            )

    updated = {k: v for k, v in state.items()}
    updated[identifier] = capability

    return updated


def _do_revoke(capability, request, state):
    return state


def _do_validate(capability, request, state):
    return state


def parse_args(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        '-C', '--connect',
        default=VALIDATOR_DEFAULT_URL,
        help='Endpoint for the validator connection')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=2,
                        help='Increase output sent to stderr')

    parser.add_argument(
        '-V', '--version',
        action='version',
        version= 'sawtooth-'+ FAMILY_NAME + ' (Hyperledger Sawtooth) version ' + FAMILY_VERSION,
        help='print version information')

    return parser.parse_args(args)


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    opts = parse_args(args)
    processor = None
    try:
        processor = TransactionProcessor(url=opts.connect)
        log_config = get_log_config(filename="capbac_log_config.toml")

        # If no toml, try loading yaml
        if log_config is None:
            log_config = get_log_config(filename="capbac_log_config.yaml")

        if log_config is not None:
            log_configuration(log_config=log_config)
        else:
            log_dir = get_log_dir()
            # use the transaction processor zmq identity for filename
            log_configuration(
                log_dir=log_dir,
                name="capbac-" + str(processor.zmq_id)[2:-1])

        init_console_logging(verbose_level=opts.verbose)

        # The prefix should eventually be looked up from the
        # validator's namespace registry.
        handler = CapBACTransactionHandler()

        processor.add_handler(handler)

        processor.start()

    except KeyboardInterrupt:
        pass
    except Exception as e:  # pylint: disable=broad-except
        print("Error: {}".format(e), file=sys.stderr)
    finally:
        if processor is not None:
            processor.stop()
