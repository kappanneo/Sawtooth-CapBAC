# sawtooth-capbac

Sawtooth transaction family for Capability Based Access Control.

## version / token format

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
capbac issue <token as JSON>
```

Example of token to be issued: (signature and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "IS": "root@raspi",
        "SU": "0256fc4f4705582d591bb4a636da729e00d77b17dd351587d07bbeefea5dc636d7",
        "DE": "raspi",
        "NB": "1525691114",
        "NA": "1530691114",
        "PA": "0123456789abcdef"
    }

Corresponding command:

```bash
capbac issue '{"ID":"0123456789abcdef","IS":"root@raspi","SU":"0256fc4f4705582d591bb4a636da729e00d77b17dd351587d07bbeefea5dc636d7","DE":"raspi","NB":"1525691114","NA":"1530691114","PA":"0123456789abcdef"}'
```

### list subcommand

```bash
capbac list <device URI>
```

Following previous example:

```bash
capbac list raspi
```