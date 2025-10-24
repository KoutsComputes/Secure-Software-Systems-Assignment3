#!/bin/sh
# Periodic logical backups of the primary DB
# Stored with LF endings for compatibility in Linux containers.
set -eu

mkdir -p /backups
echo "Starting periodic backups to /backups"

while true; do
  TS=$(date +%Y%m%d-%H%M%S)
  mysqldump -h db -u root -p"${MYSQL_ROOT_PASSWORD}" --databases flask_db > \
    "/backups/flask_db-${TS}.sql" || echo "Backup failed at ${TS}" >&2
  sleep 21600
done

