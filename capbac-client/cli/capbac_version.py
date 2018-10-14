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

FAMILY_NAME = 'capbac'
FAMILY_VERSION = '1.0'
IDENTIFIER_LENGTH = 16
TIMESTAMP_LENGTH = 10
MAX_URI_LENGTH = 2000
PUBLICKEY_LENGTH = 66
SIGNATURE_LENGTH = 128

REQUEST_ACTIONS = {'GET','POST','PUT','DELETE'}

PAYLOAD_FORMAT = {
    'AC': {
        'description': 'action',
        'allowed values': {'issue','revoke'}
    },
    'OB': {
        'description': 'action\'s object',
        'allowed types': {type({})}
    }
}

CAPABILITY_FORMAT = {
    'ID': {
        'description': 'token identifier',
        'len': IDENTIFIER_LENGTH
    },
    'II': {
        'description': 'issue istant',
        'len': TIMESTAMP_LENGTH
    },
    'VR':{
        'description': 'version',
        'allowed values': {FAMILY_VERSION}
    },
    'SU': {
        'description': 'subject\'s public key',
        'len': PUBLICKEY_LENGTH
    },
    'DE': {
        'description': 'device\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'AR': {
        'description': 'access rights',
        'allowed types': {list},
    },
    'NB': {
        'description': 'not before time',
        'len': TIMESTAMP_LENGTH
    },
    'NA': {
        'description': 'not after time',
        'len': TIMESTAMP_LENGTH
    },
    'IC': {
        'description': 'issuer capability (parent token identifier)',
        'allowed types': {type(None), str},
        'len': IDENTIFIER_LENGTH
    },
    'SI': {
        'description': 'issuer\'s signature',
        'len': SIGNATURE_LENGTH
    }
}

ACCESS_RIGHT_FORMAT = {
    'AC': {
        'description': 'permitted action',
        'allowed values': REQUEST_ACTIONS,
    },
    'RE': {
        'description': 'resource',
        'max_len': MAX_URI_LENGTH
    },
    'DD': {
        'description': 'delegation depth',
        'allowed types': {int}
    }
}

REVOCATION_FORMAT = {
    'ID': {
        'description': 'identifier of the revoked token',
        'len': IDENTIFIER_LENGTH
    },
    'II': {
        'description': 'issue istant',
        'len': TIMESTAMP_LENGTH
    },
    'VR':{
        'description': 'version',
        'allowed values': {FAMILY_VERSION}
    },
    'DE': {
        'description': 'device\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'RT': {
        'description': 'revocation type',
        'allowed values': {'ICO','ALL','DCO'}
    },
    'IC': {
        'description': 'issuer capability',
        'allowed types': {type(None), str},
        'len': IDENTIFIER_LENGTH
    },
    'SI': {
        'description': 'issuer\'s signature',
        'len': SIGNATURE_LENGTH
    }
}

VALIDATION_FORMAT = {
    'II': {
        'description': 'issue istant',
        'len': TIMESTAMP_LENGTH
    },
    'VR':{
        'description': 'version',
        'allowed values': {FAMILY_VERSION}
    },
    'DE': {
        'description': 'device\'s URI',
        'max_len': MAX_URI_LENGTH
    },
    'AC': {
        'description': 'requested action',
        'allowed values': REQUEST_ACTIONS,
    },
    'RE': {
        'description': 'resource',
        'max_len': MAX_URI_LENGTH
    },
    'IC': {
        'description': 'requester\'s capability',
        'len': IDENTIFIER_LENGTH
    },
    'SI': {
        'description': 'requester\'s signature',
        'len': SIGNATURE_LENGTH
    }
}
