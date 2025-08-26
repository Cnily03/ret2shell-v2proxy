# ret2shell-v2proxy

Docker registry API for Ret2Shell. External deployment.

## Deployment

You need to pass `config.toml` to `/etc/passwd`, and ensure the database and registry can be visited.

```yaml

name: ret2shell

services:

  database:
    image: postgres:16-alpine
    # ...

  platform:
    image: ret2shell:latest
    volumes:
      - ./config:/etc/ret2shell:ro
      # ...
    # ...

  v2proxy:
    image: r2s-v2proxy:latest
    build: .
    depends_on:
      - platform
    environment:
      - V2_SERVICE: ret2shell
    # extra_hosts:
    #   - host.docker.internal:host-gateway
    volumes:
      - ./config:/etc/ret2shell:ro
    ports:
      - 1331:1331

```
