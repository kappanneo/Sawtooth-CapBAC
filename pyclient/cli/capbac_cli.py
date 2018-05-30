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

import argparse
import getpass
import logging
import os
import sys
import traceback

from colorlog import ColoredFormatter

from cli.capbac_client import CapBACClient
from cli.capbac_exceptions import CapBACCliException
from cli.capbac_exceptions import CapBACClientException

FAMILY_NAME = 'capbac'
FAMILY_VERSION = '1.0'

DEFAULT_URL = 'http://rest-api:8008'

def create_console_handler(verbose_level=2):
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

    if verbose_level == 0:
            clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog

def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))

def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version= 'sawtooth-'+ FAMILY_NAME + ' (Hyperledger Sawtooth) version ' + FAMILY_VERSION,
        help='display version information')

    return parent_parser

def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage the access capabilities',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_issue_parser(subparsers, parent_parser)
    add_revoke_parser(subparsers, parent_parser)
    add_validate_parser(subparsers, parent_parser)

    return parser

def add_issue_parser(subparsers, parent_parser):
    message = 'Sends a capbac transaction to store the capability token in the ledger.'

    parser = subparsers.add_parser(
        'issue',
        parents=[parent_parser],
        description=message,
        help='issue a capability token')

    parser.add_argument(
        'capability',
        type=str,
        help='capability token as JSON')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

def do_issue(args):
    capability  = args.capability
    client = _get_client(args)
    response = client.issue(capability)
    print("Response: {}".format(response))

def add_revoke_parser(subparsers, parent_parser):
    message = 'Sends a capbac transaction to delete one or more capabilities from the ledger, according to the revocation request (requires a revocation capability).'

    parser = subparsers.add_parser(
        'revoke',
        parents=[parent_parser],
        description=message,
        help='revoke an issued capability token')

    parser.add_argument(
        'capability',
        type=str,
        help='revocation capability as JSON')

    parser.add_argument(
        'request',
        type=str,
        help='request specifing the capabilities to be revoked as JSON')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

def do_revoke(args):
    capability, request = args.capability, args.requeest
    client = _get_client(args)
    response = client.revoke(capability, request)
    print("Response: {}".format(response))

def add_validate_parser(subparsers, parent_parser):
    message = 'Sends a capbac transaction to check if the request matches the capability token stored in the ledger.'

    parser = subparsers.add_parser(
        'validate',
        parents=[parent_parser],
        description=message,
        help='check if the capability is valid for the request')

    parser.add_argument(
        'capabiltiy',
        type=str,
        help='capability as JSON')

    parser.add_argument(
        'request',
        type=str,
        help='access request as JSON')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")


def do_validate(args):
    capability, request = args.capability, args.request
    client = _get_client(args)
    response = client.validate(capability, request)
    print("Response: {}".format(response))

def add_list_parser(subparsers, parent_parser):
    message = 'List all capability tokens issued for the specified device.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='List all capabilites for a device')

    parser.add_argument(
        'device',
        type=str,
        help='URI of the device')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

def do_list(args):
    device = args.device
    client = _get_client(args)
    token_list = client.list(device)
    print(token_list)


def _get_client(args):
    return CapBACClient(
        url=DEFAULT_URL if args.url is None else args.url,
        keyfile=_get_keyfile(args))


def _get_keyfile(args):
    try:
        if args.keyfile is not None:
            return args.keyfile
    except AttributeError:
        return None

    real_user = getpass.getuser()
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, real_user)

# Main

def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    if args.verbose is None:
        verbose_level = 2
    else:
        verbose_level = args.verbose
    setup_loggers(verbose_level=verbose_level)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Get the commands from cli args and call corresponding handlers
    if   args.command == 'issue':    do_issue(args)
    elif args.command == 'revoke':   do_revoke(args)
    elif args.command == 'validate': do_validate(args)
    elif args.command == 'list':     do_list(args)
    else:
        raise CapBACCliException("Invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except (CapBACCliException, CapBACClientException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
