# docker

## MySQL 8.0

Need to change settings in my.cnf
```
[mysqld]
default_authentication_plugin= mysql_native_password
```

Then login
```
$ docker-compose exec mysql bash
$ mysql -u root -p 
(login as root)

ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'root';
ALTER USER 'default'@'%' IDENTIFIED WITH mysql_native_password BY 'secret';
```
then go to phpmyadmin and login as :
```
host -> mysql
user -> root
password -> root
```
