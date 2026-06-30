#!/bin/sh
set -e
chown -R vigil:vigil /app/data_volume /app/backups
exec gosu vigil "$@"
