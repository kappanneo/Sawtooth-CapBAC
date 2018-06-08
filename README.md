# sawtooth-capbac

Sawtooth transaction family for Capability Based Access Control.

## version format

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

    TOKEN_FORMAT = {
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
        'IS': {
            'description': 'issuer\'s URI',
            'max_len': MAX_URI_LENGTH
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
        'IS': {
            'description': 'issuer\'s URI',
            'max_len': MAX_URI_LENGTH
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

## build

```bash
cd sawtooth-capbac
docker-compose up --build
```

## run

Start the client on another terminal:

```bash
docker exec -it capbac-client bash
```

In the clent bash:

```bash
sawtooth keygen # create RSA key pair for authentication
```

### capbac issue

```bash
capbac issue [--root] <token as JSON>
```

Example of root token to be issued: (subject, issuer capability, signature, version and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "IS": "claudio@unipg.it",
        "DE": "coap://light.b1.unipg.it",
        "AR": [{
            "AC": "GET",
            "RE": "light",
            "DD": 4
        }, {
            "AC": "PUT",
            "RE": "off",
            "DD": 3
        }],
        "NB": "1525691114",
        "NA": "1530691114"
    }

Corresponding command:

```bash
capbac issue --root '{"ID":"0123456789abcdef","IS":"claudio@unipg.it","DE":"coap://light.b1.unipg.it","AR":[{"AC":"GET","RE":"light","DD":4},{"AC":"PUT","RE":"off","DD":3}],"NB":"1525691114","NA":"1530691114"}'
```

For testing purposes we can create a new sawtooth identitied with:

```bash
sawtooth keygen <name>
```

The public key for the dependant capabilty:

```bash
cat /root/.sawtooth/keys/<name>.pub
```

To use the client as subject:

```bash
capbac <subcommand> --keyfile /root/.sawtooth/keys/<name>.priv
```

In order for the next examples to be consistent copy-paste the keys with:

```bash
echo 02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea >> /root/.sawtooth/keys/subject.pub
echo 6abd5b5251d0f3f98c75f77a851e71aedc44555f39775a432f6783bb445dea1b >> /root/.sawtooth/keys/subject.priv
```

Example of capability dependant on the previous one: (signature, version and timestamp sill added by the client)

    {
        "ID": "0123456789abcde1",
        "IS": "claudio@unipg.it",
        "SU": "02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea",
        "DE": "coap://light.b1.unipg.it",
        "AR": [{
            "AC": "GET",
            "RE": "light",
            "DD": 0
        }],
        "NB": "1525691114",
        "NA": "1530691114",
        "IC": "0123456789abcdef"
    }

Corresponding command:

```bash
capbac issue '{"ID":"0123456789abcde1","IS":"claudio@unipg.it","SU":"02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea","DE":"coap://light.b1.unipg.it","AR":[{"AC":"GET","RE":"light","DD":0}],"NB":"1525691114","NA":"1530691114","IC":"0123456789abcdef"}'
```

Now "subject" should be able to access "light"

### capbac submit

```bash
capbac submit <access request as JSON>
```

Example of access request: (signature, version and timestamp are added by the client)

    {
        "DE": "coap://light.b1.unipg.it",
        "AC": "GET",
        "RE": "light",
        "IC": "0123456789abcde1"
    }

Corresponding command:

```bash
capbac submit --keyfile /root/.sawtooth/keys/subject.priv '{"DE":"coap://light.b1.unipg.it","AC":"GET","RE":"light","IC":"0123456789abcde1"}'
```

Output: (prettified)
{
    "VR": "1.0",
    "DE": "coap://light.b1.unipg.it",
    "IC": "0123456789abcde1",
    "II": "1528492264",
    "SI": "0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d",
    "RE": "light",
    "AC": "GET"
}

### capbac validate

```bash
capbac validate <access request as JSON>
```

Command corresponding to the output from previous example:

```bash
capbac validate --keyfile /root/.sawtooth/keys/subject.priv '{"VR":"1.0","DE":"coap://light.b1.unipg.it","IC":"0123456789abcde1","II":"1528492264","SI":"0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d","RE":"light","AC":"GET"}'
```

### capbac list

```bash
capbac list <device URI>
```

Following previous example:

```bash
capbac list coap://light.b1.unipg.it
```

### capbac revoke

```bash
capbac revoke <revocation request as JSON>
```

Example of revocation request: (signature, version and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "IC": "0123456789abcdef",
        "IS": "claudio@unipg.it",
        "DE": "coap://light.b1.unipg.it",
        "RT": "ALL"
    }

Corresponding command:

```bash
capbac revoke '{"ID":"0123456789abcdef","IC":"0123456789abcdef","IS":"claudio@unipg.it","DE":"coap://light.b1.unipg.it","RT":"ALL"}'
```