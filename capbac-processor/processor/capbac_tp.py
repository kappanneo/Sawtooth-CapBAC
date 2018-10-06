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

from sawtooth_signing import create_context
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging
from sawtooth_sdk.processor.log import log_configuration
from sawtooth_sdk.processor.config import get_log_config
from sawtooth_sdk.processor.config import get_log_dir

from processor.capbac_version import *

LOGGER = logging.getLogger(__name__)

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
        action, obj, device, capability, sender = _unpack_and_verify(transaction)

        # State retrival and update
        state = _get_state_data(device, context)

        updated = _do_capbac(action, obj, capability, sender, state)

        _set_state_data(device, updated, context)

def _unpack_and_verify(transaction):

    sender_key_str = transaction.header.signer_public_key

    try:
        payload = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')

    _check_format(payload,"payload",PAYLOAD_FORMAT)

    action = payload['AC']
    obj = payload['OB']

    if action == 'issue':

        _check_format(obj,'capability token',TOKEN_FORMAT)

        # time interval logical check
        try:
            not_before = int(obj['NB'])
            not_after =  int(obj['NA'])
        except:
            raise InvalidTransaction('Invalid token: timestamp not a number')

        if not_before > not_after:
            raise InvalidTransaction("Invalid token: incorrect time interval")

        # check if expired
        now = int(time.time())
        if now >= not_after:
            raise InvalidTransaction("Invalid token: token expired")

        capability = obj['IC']
        if not capability: # only allowed if root token
            if obj['SU'] != sender_key_str:
                raise InvalidTransaction(
                    'Invalid capability: "IC" cannot be null for non-root tokens.')

    elif action == 'revoke':

        _check_format(obj,'revocation request',REVOCATION_FORMAT)

        capability = obj['IC']

    signature = obj.pop('SI')

    _check_signature(obj,signature,sender_key_str)

    device = obj.pop('DE')

    return action, obj, device, capability, sender_key_str

def _check_signature(obj,signature,sender_key_str):
    publicKey = Secp256k1PublicKey.from_hex(sender_key_str)
    token_string = str(cbor.dumps(obj,sort_keys=True)).encode('utf-8')
    if not create_context('secp256k1').verify(signature,token_string,publicKey):
        raise InvalidTransaction('Invalid signature.')

def _check_format(dictionary,name,dictionary_format,subset=None):
    if subset is None:
        subset = set(dictionary_format)
    for label in subset:
        if label not in dictionary:
            raise InvalidTransaction("Invalid {}: {} missing ({})"
            .format(name,label,dictionary_format[label]['description']))
        feature = dictionary[label]
        if 'allowed values' in dictionary_format[label]:
            if feature not in dictionary_format[label]['allowed values']:
                raise InvalidTransaction(
                "Invalid {}: {} value should be one the following: {}"
                .format(name,label,dictionary_format[label]['allowed values']))
        elif 'allowed types' in dictionary_format[label]:
            if type(feature) not in dictionary_format[label]['allowed types']:
                raise InvalidTransaction(
                "Invalid {}: {} type not allowed".format(name,label))
        elif type(feature) == str: # string allowed by default
            if 'len' in dictionary_format[label]:
                if len(feature) != dictionary_format[label]['len']:
                    raise InvalidTransaction(
                        "Invalid {}: {} length should be {}"
                        .format(name,label,dictionary_format[label]['len']))
            elif 'max_len' in dictionary_format[label]:
                if len(feature) > dictionary_format[label]['max_len']:
                    raise InvalidTransaction(
                        "Invalid {}: {} length should less than {}"
                        .format(name,label,dictionary_format[label]['max_len']))
        else:
            raise InvalidTransaction(
                "Invalid {}: {} should be a string".format(name,label))
    for label in dictionary:
        if label not in subset:
            raise InvalidTransaction("Invalid {}: unexpected label {}".format(name,label))

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


def _do_capbac(action, obj, capability, sender, state):
    if action == 'issue':
        return _do_issue(obj, capability, sender, state)
    elif action == 'revoke':
        return _do_revoke(obj, capability, sender, state)
    else:
        raise InternalError('Unandled action: {}'.format(action))


def _do_issue(token, parent, subject, state):
    identifier = token.pop('ID')
    msg = 'Issuing capbabiltity token with ID: {}'.format(identifier)
    LOGGER.debug(msg)

    if identifier in state:
        raise InvalidTransaction(
            'Cannot issue: capability token with ID = {} already exists'
            .format(identifier))

    now = int(time.time())

    LOGGER.debug('Checking authorization')
    # check authorization
    if parent != None:
        if parent not in state:
            raise InvalidTransaction(
                'Cannot issue: no parent capability token with ID = {}'.format(parent))
        if state[parent]['SU'] != subject:
            raise InvalidTransaction('Cannot issue: issuer is not the subject of parent capability')

    LOGGER.debug('Reformatting access rights')
    # reformat access rights
    new_format = {}
    for access_right in token['AR']:
        new_format.setdefault(access_right['RE'],{})
        new_format[access_right['RE']].update({access_right['AC']:access_right['DD']})
    token['AR'] = new_format

    LOGGER.debug('Checking delegation chain')
    # delegation chain check
    current_token = token
    while parent != None:
        if parent not in state:
            raise InvalidTransaction(
                'Cannot issue: no parent capability token with ID = {}'.format(parent))
        parent_token = state[parent]

        # check time interval
        if now >= int(parent_token['NA']):
            raise InvalidTransaction(
                'Cannot issue: parent capability token with ID = {} expired'
                .format(parent))
        if now < int(parent_token['NB']):
            raise InvalidTransaction(
                'Cannot issue: capability token with ID = {} still not active'
                .format(parent))

        # check access rights
        for resource in current_token["AR"]:
            if resource not in parent_token["AR"]:
                raise InvalidTransaction(
                    'Cannot issue: resource {} not authorized in parent token ID = {}'
                    .format(resource, parent))
            for action in current_token["AR"][resource]:
                if action not in parent_token["AR"][resource]:
                    raise InvalidTransaction(
                        'Cannot issue: action {} not authorized for resource {} in parent token ID = {}'
                        .format(action,resource, parent))
                if not current_token["AR"][resource][action] < parent_token["AR"][resource][action]:
                    raise InvalidTransaction(
                        'Cannot issue: delegation should be less than parent for action {},\
                         resource {}, parent token ID = {}'
                        .format(action,resource, parent))

        # next
        current_token = parent_token
        parent = current_token['IC']

    # version is already checked and not required anymore
    token.pop('VR')

    state[identifier] = token

    return state


def _do_revoke(request, capability, requester, state):
    identifier = request['ID']
    msg = 'Revoking capbabiltity token with ID: {}'.format(identifier)
    LOGGER.debug(msg)

    # check existence of target
    if identifier not in state:
        raise InvalidTransaction(
            'Cannot revoke: target capability token ({}) do not exists'
            .format(identifier))

    # check authorization
    if capability not in state:
        raise InvalidTransaction(
            'Cannot revoke: no capability token with ID = {}'.format(capability))
    if state[capability]['SU'] != requester:
        raise InvalidTransaction('Cannot revoke: requester is not the subject of the sent capability')

    LOGGER.debug('Checking delegation chain')
    # chek if revoker's token is anchestor of revoked
    if capability != identifier: # target is its own capability => no need to check
        current_token = state[identifier]
        parent = current_token['IC']
        while parent != None and parent != capability:
            if parent not in state:
                raise InternalError('Broken chain')
            # next
            current_token = state[parent]
            parent = current_token['IC']
        if parent is None:
            raise InvalidTransaction('Cannot revoke: requester capability has no right over target capability')

    # delegation chain check
    now = int(time.time())
    current_token = state[capability]
    parent = current_token['IC']
    while parent != None:
        if parent not in state:
            raise InternalError('Broken chain')

        # check time interval
        if now >= int(current_token['NA']):
            raise InvalidTransaction(
                'Cannot revoke: capability token with ID = {} expired'
                .format(parent))
        if now < int(current_token['NB']):
            raise InvalidTransaction(
                'Cannot revoke: capability token with ID = {} still not active'
                .format(parent))

        # next
        current_token = state[parent]
        parent = current_token['IC']

    LOGGER.debug('Removing token')
    # revocation
    revocation_type = request['RT']
    if revocation_type == 'ICO': # Identified Capability Only
        if state[identifier]['IC'] is None:
            raise InvalidTransaction(
                'Cannot revoke: invalid revocation type for root capability')
        else:
            for token in state: # assign childs to grampa
                if state[token]['IC'] == identifier:
                    state[token]['IC'] = state[identifier]['IC']
    else:
        state =_recursively_remove_childs(state, identifier)

    if revocation_type != 'DCO': # Dependant Capability Only
        state.pop(identifier)

    LOGGER.info('Token removed.')

    return state

def _recursively_remove_childs(state, parent):
    for token in set(state):
        if state[token]['IC'] == parent:
            state = _recursively_remove_childs(state, token)
            state.pop(token)
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
                name=FAMILY_NAME+ "-" + str(processor.zmq_id)[2:-1])

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
