# sawtooth-capbac

Sawtooth transaction family for Capability Based Access Control.

### build test

```bash
cd sawtooth-capbac/test
docker-compose up --build
```

### capbac issue

Attach Device on another terminal:

```bash
docker exec -it device bash
```

Issue a token:

```bash
capbac issue [--root] <token as JSON>
```

*For more datails on the token structure see [capbac_version.py](https://gitlab.com/kappanneo/sawtooth-capbac/blob/master/capbac_version.py)

Example of root token to be issued: (subject,issuer capability, signature, version and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "DE": "coap://device",
        "AR": [{
            "AC": "GET",
            "RE": "light",
            "DD": 5
        }, {
            "AC": "GET",
            "RE": "resource",
            "DD": 1
        }, {
            "AC": "PUT",
            "RE": "resource",
            "DD": 0
        }],
        "NB": "1525691114",
        "NA": "1540691114"
    }

Corresponding command:

```bash
capbac issue --root '{"ID":"0123456789abcdef","DE":"coap://device","AR":[{"AC":"GET","RE":"light","DD":5},{"AC":"GET","RE":"resource","DD":1},{"AC":"PUT","RE":"resource","DD":0}],"NB":"1525691114","NA":"1540691114"}'
```

Expected output:

    Response: {
    "link": "http://rest-api:8008/batch_statuses?id=03801c90832d78fe3de5e37d4a094f9a73f80647f66aea49770b75c83830675e50439223c6c440d9ba4f199a7e2dc63a2dabef173d53544a8aa9e43808f4c3ff"
    }

Access link with curl:
```bash
curl <link>
```

Expected output:

    {
    "data": [
        {
        "id": "03801c90832d78fe3de5e37d4a094f9a73f80647f66aea49770b75c83830675e50439223c6c440d9ba4f199a7e2dc63a2dabef173d53544a8aa9e43808f4c3ff",
        "invalid_transactions": [],
        "status": "COMMITTED"
        }
    ],
    "link": "http://rest-api:8008/batch_statuses?id=03801c90832d78fe3de5e37d4a094f9a73f80647f66aea49770b75c83830675e50439223c6c440d9ba4f199a7e2dc63a2dabef173d53544a8aa9e43808f4c3ff"
    }

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

Example of capability dependant on the previous one: (signature, version and timestamp sill added by the client)

    {
        "ID": "0123456789abcde1",
        "IS": "claudio@unipg.it",
        "SU": "02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea",
        "DE": "coap://device",
        "AR": [{
            "AC": "GET",
            "RE": "light",
            "DD": 0
        }],
        "NB": "1525691114",
        "NA": "1540691114",
        "IC": "0123456789abcdef"
    }

Corresponding command:

```bash
capbac issue '{"ID":"0123456789abcde1","SU":"02b6b9f80ee44f5d711592def2a42941c66f461a9dbb5bf5d164c6d8b35ced8aea","DE":"coap://device","AR":[{"AC":"GET","RE":"light","DD":0}],"NB":"1525691114","NA":"1540691114","IC":"0123456789abcdef"}'
```

Now "subject" should be able to access "light" -->

<!-- ### capbac submit

```bash
capbac submit <access request as JSON>
```

Example of access request: (signature, version and timestamp are added by the client)

    {
        "DE": "coap://device",
        "AC": "GET",
        "RE": "light",
        "IC": "0123456789abcde1"
    }

Corresponding command:

```bash
capbac submit --keyfile /root/.sawtooth/keys/subject.priv '{"DE":"coap://device","AC":"GET","RE":"light","IC":"0123456789abcde1"}'
```

Output: (prettified)

    {
        "VR": "1.0",
        "DE": "coap://device",
        "IC": "0123456789abcde1",
        "II": "1528492264",
        "SI": "0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d",
        "RE": "light",
        "AC": "GET"
    } -->

<!-- ### capbac validate

```bash
capbac validate <access request as JSON>
```

Command corresponding to the output from previous example:

```bash
capbac validate '{"VR":"1.0","DE":"coap://device","IC":"0123456789abcdef","II":"1528492264","SI":"0bd47d10f76926f597196b1ba326c597c34504c9936eeee763cf902f90e5d3640c10531aa0e32c48c7711f3d018a27f5b980f0276a5842fcbbf38a0d5f704c2d","RE":"light","AC":"GET"}'
```
 -->
### capbac list

```bash
capbac list <device URI>
```

Following previous example:

```bash
capbac list coap://device
```

Expected output:

    {
        "0123456789abcdef": {
            "AR": {
                "light": [
                    {
                        "GET": 5
                    }
                ],
                "resource": [
                    {
                        "GET": 1
                    },
                    {
                        "PUT": 0
                    }
                ]
            },
            "IC": null,
            "II": "1538842506",
            "NA": "1540691114",
            "NB": "1525691114",
            "SU": "023935c4b863f4494388ff1190993594efbfc932e9e02b811b780f263635181b80"
        }
    }

### capbac revoke

```bash
capbac revoke <revocation request as JSON>
```

Example of revocation request: (signature, version and timestamp are added by the client)

    {
        "ID": "0123456789abcdef",
        "IC": "0123456789abcdef",
        "DE": "coap://device",
        "RT": "ALL"
    }

Corresponding command:

```bash
capbac revoke '{"ID":"0123456789abcdef","IC":"0123456789abcdef","DE":"coap://device","RT":"ALL"}'
```

### coap

Attach Subject on another terminal:

```bash
docker exec -it subject bash
```

Example of CoAP request to Device:

```bash
aiocoap-client coap://device/time
```
