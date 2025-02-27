# NumericalOJ
An online-judge system for MATLAB, Baltamatica or Octave, easy to deploy.

### Requirement

- Ubuntu or Debian.

- One of them: MATLAB, Baltamatica, Octave
  - **Note:** The default setting is Ovtave, which can be installed with
  
    ```bash
    sudo apt install octave
    ```
  
    If you want others, you should edit `judger/app.py`. I'm sure you will know how to edit once you see the code.
  
- MySQL

  ```bash
  wget https://repo.mysql.com/apt/debian/pool/mysql-apt-config/m/mysql-apt-config/mysql-apt-config_0.8.29-1_all.deb
  sudo dpkg -i mysql-apt-config_0.8.29-1_all.deb 
  sudo apt update
  sudo apt install mysql-server
  ```

- Redis

  ```bash
  sudo apt insatll redis-server
  sudo systemctl start redis-server
  sudo systemctl enable redis-server
  ```

- Python3

  ```bash
  sudo apt install python3
  ```

- Some Python packages which can be installed by pip
  ```bash
  pip3 install pymysql markdown werkzeug flask celery 
  ```
  
  Test with `python3 oj.py`. If it not works, install the missing packages according to your error message.
  
- An email adress with SMTP survice. (See https://mail.163.com)

- supervisor

  ```bash
  sudo apt install supervisor
  ```

### Deployment (for use)

1. Create a MySQL database:

   ```mysql
   mysql -u [username] -p -e "CREATE DATABASE myojdb;"
   ```

   Import the database:

   ```mysql
   mysql -u [username] -p myojdb < myojdb.sql
   ```

2. Complete the configures in `config.py`.

3. Start the service:

   ```bash
   cd judger
   supervisord -c judger.conf
   cd ..
   supervisord -c celery.conf
   supervisord -c web.conf
   ```
