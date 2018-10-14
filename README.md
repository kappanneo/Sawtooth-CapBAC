# sawtooth-capbac

[Sawtooth](https://github.com/hyperledger/sawtooth-core) transaction family for [Capability Based Access Control](https://www.sciencedirect.com/science/article/pii/S089571771300054X).

## Testing environment

```bash
cd sawtooth-capbac/test/
```

*Requires [Docker Engine](https://docs.docker.com/install/) (17.03.0-ce or higher) and and [Docker Compose](https://docs.docker.com/compose/install/).


### Build and start

```bash
docker-compose up --build
```

### Stop and clean

```bash
docker-compose down
```
*Stopping the processes is not enough for a clean restart (issued tokens will stay).

### Restart
```bash
docker-compose up
```

### Exec commands


```bash
docker exec <container name> <command>
```
*For more information see [docker exec](https://docs.docker.com/engine/reference/commandline/exec/).


### Attach a container

```bash
docker exec -it <container name> bash
```

Detach with:
```bash
exit
```


## Walkthrough

*Examples require the testing environment to be up and running.

### List capabilities

```bash
capbac list <server URI>
```
*The **capbac** command can run on any docker container featuring a [capbac-client](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac-client/) (*device*, *subject* or *issuer*).

In our scenario *device* is running a [CoAP](https://en.wikipedia.org/wiki/Constrained_Application_Protocol) server, so we run:
```
capbac list coap://device
```


Using **docker exec** to run direclty on *subject*:

```
docker exec subject capbac list coap://device
```

Expected output if no capability token has been issued (only the root token is shown):

```json
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
```

*Subject's public key (SU) and "Not Before" time (NB) will differ.


### Issue a capability token

```bash
capbac issue [--root] <token as JSON string>
```

*For more datails on the capability token format see [capbac_version.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac_version.py).

Root token issued by *device* before starting the CoAP sever (python dict from [test/Device/coap-server.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/test/Device/coap-server.py)):

```python
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
```
*The timestamp and the signature are not required since they are added by the [capbac-client](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac-client/) when using **capbac issue**. Also, since this is a root token, the issuer's capability is always **null** and the public key of the subject is the same one of the issuer, so both are not required either.

Command used (from the same file):
```python
["capbac","issue","--root",json.dumps(capability_token)]
```
*If an error occurs during the issuing of the root token (e.g. a root token for that resource is already committed) the server will not start.

This gives *device* the control over the access rights for its resources.

*device* can delegate the access rights administation to a different device by issuing a new token dependant on the root one.

Example of dependant token (can only be issued by *device*):

```python
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
```
*The public key of the issuer, the timestamp and the signature are not required since they are added by the [capbac-client](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac-client/) when using **capbac issue --root**.

Corresponding command with *issuer* as the subject of the token:

```bash
docker exec device capbac issue '{"ID":"0000000000000001","DE":"coap://device","AR":[{"AC":"GET","RE":"time","DD":99},{"AC":"GET","RE":"resource","DD":99},{"AC":"PUT","RE":"resource","DD":99}],"NB":"1525691114","NA":"1540691114","IC":"0000000000000000","SU":"'$(docker exec issuer cat /root/.sawtooth/keys/root.pub)'"}'
```
*In a real scenario *device* will know *issuer*'s public key (as every one else), but here we exploit **docker exec** to retrieve it.

Expected output:
```json
{
"link": "http://rest-api:8008/batch_statuses?id=2d3a434d275fdd2e0f4723e6f8bcfa1968ae9bb3b60d44dca982d5f05982017f2f9c6b31425187bfbad2f9b74d2bddc45b87d185f9bf79afaa91f6d100efdb45"
}
```
*Identifiers will always differ.

Access link using **curl**:
```bash
docker exec device curl <link>
```

Expected output:
```json
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
```
Now *issuer* can manage the access rights for the resources in *device*. He does that by issuing more tokens.

Example of token that can be issued by *issuer*:

```python
{
    "ID": "0000000000000002",
    "DE": "coap://device",
    "AR": [{
        "AC": "GET",
        "RE": "resource",
        "DD": 0
    }, {
        "AC": "PUT",
        "RE": "resource",
        "DD": 0
    }],
    "NB": "1525691114",
    "NA": "1540691114",
    "IC": "0000000000000001",
    "SU": <public key of the subject>
}
```
Correspondong command with *subject* as the subject of the token:
```bash
docker exec issuer capbac issue '{"ID":"0000000000000002","DE":"coap://device","AR":[{"AC":"GET","RE":"resource","DD":0},{"AC":"PUT","RE":"resource","DD":0}],"NB":"1525691114","NA":"1540691114","IC":"0000000000000001","SU":"'$(docker exec subject cat /root/.sawtooth/keys/root.pub)'"}'
```

If the token is committed, *subject* will be able to perform PUT and GET requests on *resouce*.
*subject* will not be able to delegate this capabilities any further since for both the Delegation Depth (DD) is set to zero.

### Request a resource

Using the simple client from [aiocoap](https://aiocoap.readthedocs.io/en/latest/module/aiocoap.cli.client.html) one can send CoAP requests with:

```bash
aiocoap-client [-m <method>] [--payload <payload string>] <resource URI>
```
However, since our CoAP server is CapBAC-aware, it will always return UNAUTHORIZED unless a signed access token, pointing to a committed capability token with matchin access rights, is pre-fixed to the payload (if any, else it is sent as the payload itself). This results in the following sintax:

```bash
aiocoap-client [-m <method>] --payload "<access token JSON as string>[<payload string>]" <resource URI>
```
*For more datails on the access token format see [capbac_version.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac_version.py).

Example of access token to be signed:
```json
{
    "DE": "coap://device",
    "AC": "GET",
    "RE": "time",
    "IC": "0000000000000002"
}
```
The token is signed using **capbac sign**:
```bash
capbac sign '{"DE":"coap://device","AC":"GET","RE":"resource","IC":"0000000000000002"}'
```
Outuput (prettified):
```json
{
    "AC": "GET",
    "VR": "1.0",
    "DE": "coap://device",
    "IC": "0000000000000002",
    "SI": "c229618d223e9a1a18245bb7b2c0d9953b33981ae2f245bb1efbdcb8a9d15b8b5b64447dc6c07c883b7b40c0913b3ce4a35bf1d31c6c9f1a8bb4cede60c13756",
    "RE": "resource",
    "II": "1539261923"
}
```
*Issue Istant (II) and Version (VR) are added before the Signature (SI).

So a GET request like:

```bash
aiocoap-client coap://device/resource
```

Becomes:
```bash
aiocoap-client --payload "$(capbac sign '{"DE":"coap://device","AC":"GET","RE":"resource","IC":"0000000000000002"}')" coap://device/resource
```

Using **docker exec** on *subject*:
```bash
docker exec subject aiocoap-client --payload "$(docker exec subject capbac sign '{"DE":"coap://device","AC":"GET","RE":"resource","IC":"0000000000000002"}')" coap://device/resource
```

While a PUT request like:
```bash
aiocoap-client -m PUT --payload "some string" coap://device/resource
```
Becomes:
```bash
aiocoap-client -m PUT --payload "$(capbac sign '{"DE":"coap://device","AC":"PUT","RE":"resource","IC":"0000000000000002"}')some string" coap://device/resource
```
Using **docker exec** on *subject*:
```bash
docker exec subject aiocoap-client -m PUT --payload "$(docker exec subject capbac sign '{"DE":"coap://device","AC":"PUT","RE":"resource","IC":"0000000000000002"}')some string" coap://device/resource
```
### Revoke capabilities

```bash
capbac revoke <revocation request as JSON string>
```
*For more datails on the revocation request format see [capbac_version.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac_version.py).


Example of revocation before it is signed by **capbac revoke**:
```json
{
    "ID": "0000000000000000",
    "IC": "0000000000000000",
    "DE": "coap://device",
    "RT": "ALL"
}
```
*RT stands for "Revocation Tipe" and can be one of the following:
1. Discendant Capabilities Only (DCO)
2. Identified Capability Only (ICO)
3. Both 1. and 2. (ALL)

Corresponding command:

```bash
docker exec device capbac revoke '{"ID":"0000000000000000","IC":"0000000000000000","DE":"coap://device","RT":"ALL"}'
```
*This will remove all the capability tokens including the root one.
