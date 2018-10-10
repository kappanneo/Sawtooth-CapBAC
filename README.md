# sawtooth-capbac

[Sawtooth](https://github.com/hyperledger/sawtooth-core) transaction family for [Capability Based Access Control](https://www.sciencedirect.com/science/article/pii/S089571771300054X).

## Testing environment

Requires [Docker Engine](https://docs.docker.com/install/) (17.03.0-ce or higher) and and [Docker Compose](https://docs.docker.com/compose/install/).

### Build

```bash
cd sawtooth-capbac/test/
docker-compose up --build
```

### List tokens

```bash
capbac list <host URI>
```
*The **capbac** command can run on any docker container featuring the [capbac-client](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac-client/) (*device*, *subject* or *issuer*).

Example using [docker exec](https://docs.docker.com/engine/reference/commandline/exec/) on *subject* (*device* is hosting a [CoAP](https://en.wikipedia.org/wiki/Constrained_Application_Protocol) server):

```bash
docker exec subject capbac list coap://device
```

Expected output if no token has been issued (only the root token is showing):

    {
        "0000000000000000": {
            "AR": {
                "resource": {
                    "GET": 100,
                    "PUT": 100
                },
                "time": {
                    "GET": 100
                }
            },
            "IC": null,
            "II": "1539082955",
            "NA": "2000000000",
            "NB": "1539082954",
            "SU": "03c792d1c05a37e8b9e7afdcc9c72d6b50fd77a79631d5192f754b20202979f5af"
        }
    }

*Subject's public key (SU) and "Not Before" time (NB) will differ.


### Issue a token

```bash
capbac issue [--root] <token as JSON string>
```

*For more datails on the token structure see [capbac_version.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac_version.py)

Root token issued by *device* before starting the CoAP sever (python dict from [test/Device/coap-server.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/test/Device/coap-server.py)):

    capability_token = {
        "ID":"0000000000000000",
        "DE": "coap://device",    
        "AR": [{
            "AC": "GET",
            "RE": "time",
            "DD": 100
        }, {
            "AC": "GET",
            "RE": "resource",
            "DD": 100
        }, {
            "AC": "PUT",
            "RE": "resource",
            "DD": 100
        }],
        "NB": str(int(time.time())),
        "NA": "2000000000"
    }

Command used (from the same file):
```bash
["capbac","issue","--root",json.dumps(capability_token)]
```

This gives *device* the control over the access rights for its resources.

She can delegate the access rights administation to a different device by issuing a new token dependant on the root one.

Example of dependant token (can only be issued by *device*): 

    {
        "ID": "0000000000000001",
        "DE": "coap://device",
        "AR": [{
            "AC": "GET",
            "RE": "time",
            "DD": 99
        }, {
            "AC": "GET",
            "RE": "resource",
            "DD": 99
        }, {
            "AC": "PUT",
            "RE": "resource",
            "DD": 99
        }],
        "NB": "1525691114",
        "NA": "1540691114",
        "IC": "0000000000000000",
        "SU": <public key of the subject>
    }


Command having *issuer* as the subject of the token:

```bash
docker exec device capbac issue '{"ID":"0000000000000001","DE":"coap://device","AR":[{"AC":"GET","RE":"time","DD":99},{"AC":"GET","RE":"resource","DD":99},{"AC":"PUT","RE":"resource","DD":99}],"NB":"1525691114","NA":"1540691114","IC":"0000000000000000","SU":"'$(docker exec issuer cat /root/.sawtooth/keys/root.pub)'"}'
```

Expected output:

    Response: {
    "link": "http://rest-api:8008/batch_statuses?id=2d3a434d275fdd2e0f4723e6f8bcfa1968ae9bb3b60d44dca982d5f05982017f2f9c6b31425187bfbad2f9b74d2bddc45b87d185f9bf79afaa91f6d100efdb45"
    }

Access link using **curl**:
```bash
docker exec device curl <link>
```

Expected output:

    {
    "data": [
        {
        "id": "2d3a434d275fdd2e0f4723e6f8bcfa1968ae9bb3b60d44dca982d5f05982017f2f9c6b31425187bfbad2f9b74d2bddc45b87d185f9bf79afaa91f6d100efdb45",
        "invalid_transactions": [],
        "status": "COMMITTED"
        }
    ],
    "link": "http://rest-api:8008/batch_statuses?id=2d3a434d275fdd2e0f4723e6f8bcfa1968ae9bb3b60d44dca982d5f05982017f2f9c6b31425187bfbad2f9b74d2bddc45b87d185f9bf79afaa91f6d100efdb45"
    }

Now *issuer* can manage the access rights for the resources in *device*.

[...]

### Request a resource [currently working on authorization]

```bash
aiocoap-client [-m <method>] [--payload <payload>]<resource URI>
```
Example:

```bash
docker exec subject aiocoap-client coap://device/time
```

### Revoke a token

```bash
capbac revoke <revocation request as JSON string>
```

Example of revocation request:

    {
        "ID": "0000000000000000",
        "IC": "0000000000000000",
        "DE": "coap://device",
        "RT": "DCO"
    }

Corresponding command:

```bash
docker exec device capbac revoke '{"ID":"0000000000000000","IC":"0000000000000000","DE":"coap://device","RT":"DCO"}'
```
This command removes all the capability tokens execept for the root one.

<!-- For testing purposes we can create a new sawtooth identity with:

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

Example of capability dependant on the previous one: (signature, version and timestamp still added by the client)

    {
        "ID": "0123456789abcde1",
        "IS": "claudio@unipg.it",
        "SU": "02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea",
        "DE": "coap://device",
        "AR": [{
            "AC": "GET",
            "RE": "time",
            "DD": 0
        }],
        "NB": "1525691114",
        "NA": "1540691114",
        "IC": "0000000000000000"
    }

Corresponding command:

```bash
capbac issue '{"ID":"0123456789abcde1","SU":"02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea","DE":"coap://device","AR":[{"AC":"GET","RE":"time","DD":0}],"NB":"1525691114","NA":"1540691114","IC":"0000000000000000"}'
```

Now "subject" should be able to access "time" -->

<!-- ### capbac submit

```bash
capbac submit <access request as JSON>
```

Example of access request: (signature, version and timestamp are added by the client)

    {
        "DE": "coap://device",
        "AC": "GET",
        "RE": "time",
        "IC": "0123456789abcde1"
    }

Corresponding command:

```bash
capbac submit --keyfile /root/.sawtooth/keys/subject.priv '{"DE":"coap://device","AC":"GET","RE":"time","IC":"0123456789abcde1"}'
```

Output: (prettified)

    {
        "VR": "1.0",
        "DE": "coap://device",
        "IC": "0123456789abcde1",
        "II": "1528492264",
        "SI": "0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d",
        "RE": "time",
        "AC": "GET"
    } -->

<!-- ### capbac validate

```bash
capbac validate <access request as JSON>
```

Command corresponding to the output from previous example:

```bash
capbac validate '{"VR":"1.0","DE":"coap://device","IC":"0000000000000000","II":"1528492264","SI":"0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d","RE":"time","AC":"GET"}'
```
 -->
