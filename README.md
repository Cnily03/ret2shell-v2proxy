# ret2shell-v2proxy

Docker registry API for Ret2Shell. External deployment.

## Feature

User who have `Game` permission to specific game can push/pull `ret.sh.cn/{namespace}/{image}` where namespace can be game id or bucket. And the user can only pull `ret.sh.cn/{image}` or `ret.sh.cn/library/{image}`.

User who have both `Game` and `DevOps` permissions can push/pull `ret.sh.cn/{image}` or `ret.sh.cn/library/{image}`.

Command `docker login` is supported.

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
      LISTEN_PORT: 1331
      V2_SERVICE: ret2shell
    # extra_hosts:
    #   - host.docker.internal:host-gateway
    volumes:
      - ./config:/etc/ret2shell:ro
    ports:
      - 1331:1331

```

## License

Copyright (c) Cnily03. All rights reserved.

Licensed under the [MIT](LICENSE) license.
