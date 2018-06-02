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

    PAYLOAD_FORMAT = {
        'AC': {
            'description': 'action',
            'allowed values': {'issue'}
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
            'allowed values': {'GET','POST','PUT','DELETE'},
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

## build

```bash
cd sawtooth-capbac
docker-compose up --build
```

## run

On another terminal:

```bash
docker exec -it capbac-client bash
```

In the clent bash:

```bash
sawtooth keygen # create RSA key pair for authentication
```

### issue subcommand

```bash
capbac issue [--root] <token as JSON>
```

Example of root token to be issued: (subject, issuer capability,signature and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "IS": "root@raspi",
        "DE": "raspi",
        "AR": [{
            "AC": "GET",
            "RE": "lucky",
            "DD": 4
        }, {
            "AC": "PUT",
            "RE": "dispenser",
            "DD": 3
        }],
        "NB": "1525691114",
        "NA": "1530691114"
    }

Corresponding command:

```bash
capbac issue --root '{"ID":"0123456789abcdef","IS":"root@raspi","DE":"raspi","AR":[{"AC":"GET","RE":"lucky","DD":4},{"AC":"PUT","RE":"dispenser","DD":3}],"NB":"1525691114","NA":"1530691114"}'
```

Example of capability dependant on the previous one: (signature and timestamp sill added by the client)

    {
        "ID": "0123456789abcde1",
        "IS": "root@raspi",
        "SU": "0271469bea00095cecd2449df027b751dacfd4686d6976aa399d8269ded79d8426",
        "DE": "raspi",
        "AR": [{
            "AC": "GET",
            "RE": "lucky",
            "DD": 3
        }, {
            "AC": "PUT",
            "RE": "dispenser",
            "DD": 0
        }],
        "NB": "1525691114",
        "NA": "1530691114",
        "IC": "0123456789abcdef"
    }
    
Corresponding command:
```bash
capbac issue '{"ID":"0123456789abcde1","IS":"root@raspi","SU":"0271469bea00095cecd2449df027b751dacfd4686d6976aa399d8269ded79d8426","DE":"raspi","AR":[{"AC":"GET","RE":"lucky","DD":3},{"AC":"PUT","RE":"dispenser","DD":0}],"NB":"1525691114","NA":"1530691114","IC":"0123456789abcdef"}'
```

For testing purposes we ca create a new sawtooth identity:
```bash
sawtooth keygen subject
```
The public key for the dependant capabilty:
```bash
cat /root/.sawtooth/keys/subject.pub
```
To use the client as subject:
```bash
capbac <subcommand> --keyfile /root/.sawtooth/keys/subject.priv
```

### list subcommand

```bash
capbac list <device URI>
```

Following previous example:

```bash
capbac list raspi
```
