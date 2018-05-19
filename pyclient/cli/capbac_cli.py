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

from __future__ import print_function
import argparse
import getpass
import logging
import os
import sys
import traceback
import pkg_resources
import json

from colorlog import ColoredFormatter

from cli.capbac_client import CapBACClient
from cli.capbac_exceptions import CapBACException

FAMILY_NAME = 'capbac'
FAMILY_VERSION = '1.0'

DEFAULT_URL = 'http://rest-api:8008'

def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)
    clog.setLevel(logging.DEBUG)
    return clog

def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))

# Parsers

def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage your simple wallet',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_issue_parser(subparsers, parent_parser)

    return parser

def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version= FAMILY_NAME + ' (Hyperledger Sawtooth) version ' + FAMILY_VERSION,
        help='display version information')

    return parent_parser

def add_issue_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'issue',
        help='issue a capability token',
        parents=[parent_parser])

    parser.add_argument(
        'capability',
        type=str,
        help='the capability token')

def add_revoke_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'revoke',
        help='revoke an issued capability token',
        parents=[parent_parser])

    parser.add_argument(
        'capabiltiy',
        type=str,
        help='the capability token')

def add_access_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'access',
        help='request an access',
        parents=[parent_parser])

    parser.add_argument(
        'capabiltiy',
        type=str,
        help='the capability token')

    parser.add_argument(
        'request',
        type=str,
        help='the access request')

# Key-getters

def _get_keyfile(subject):
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, subject)

def _get_pubkeyfile(subject):
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.pub'.format(key_dir, subject)

# Handlers

def _do_issue(capability):

    keyfile = _get_keyfile(capability['IS'])

    client = CapBACClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.issue(capability)

    print("Response: {}".format(response))

# Main

def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    verbose_level = 0

    setup_loggers(verbose_level=verbose_level)

    try:
        capability = json.loads(args.capability)
    except ValueError:
        raise CapBACException("Invalid capability: not a JSON")

    # capability core check TODO: better
    if 'ID' not in capability:
        raise CapBACException("Invalid capability: 'ID' missing (token identifier)")
    elif 'IS' not in capability:
        raise CapBACException("Invalid capability: 'IS' missing (uri of issuer)")
    elif 'SU' not in capability:
        raise CapBACException("Invalid capability: 'SU' missing (public key of the subject)")
    elif 'DE' not in capability:
        raise CapBACException("Invalid capability: 'DE' missing (uri of device)")

    # Get the commands from cli args and call corresponding handlers
    if args.command == 'issue':
        _do_issue(capability)
#    elif args.command == 'revoke':
#        response = client.revoke(capability)
#    elif args.command == 'access':
#        response = client.access(capability, request)
    else:
        raise CapBACException("Invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except CapBACException as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
