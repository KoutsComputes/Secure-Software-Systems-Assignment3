-- Configure replica to follow primary using GTID auto-positioning
CHANGE MASTER TO
  MASTER_HOST='db',
  MASTER_USER='repl',
  MASTER_PASSWORD='repl_password',
  MASTER_AUTO_POSITION=1;
START SLAVE;
