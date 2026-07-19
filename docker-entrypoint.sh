#!/bin/sh
# init is idempotent: first boot provisions the operator/identity/config into the /data
# volume; later boots keep everything. Then serve on all interfaces (the container's port
# mapping is the exposure decision). Pass DELEGENT_MASTER_KEY (recommended) or the generated
# master.key lands in the volume.
set -e
delegent-gateway init --home "${DELEGENT_HOME:-/data}" --listen 0.0.0.0:8090
exec delegent-gateway serve --home "${DELEGENT_HOME:-/data}" "$@"
