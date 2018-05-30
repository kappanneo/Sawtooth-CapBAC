# sawtooth-capbac

Sawtooth transaction family for Capability Based Access Control.

## build

```bash
cd sawtooth-capbac
docker-compose up
```

## test

On another terminal:

```bash
docker exec -it capbac-client bash
```

In the clent bash:

```bash
sawtooth keygen # create RSA key pair for authentication
capbac issue <token as JSON>
```
