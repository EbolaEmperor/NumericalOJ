# NumericalOJ
An online-judge system for MATLAB, Baltamatica or Octave, easy to deploy.

### Requirement

- Ubuntu 22.04
- One of them: MATLAB, Baltamatica, Octave
  - **Note:** The default setting is Ovtave. If you want others, you should edit `judger/app.py`. I'm sure you will know how to edit once you see the code.
- MySQL
- Redis
- Python3
- Some Python packages which can be installed by pip
  - You can run `python3 oj.py`, and install the missing packages according to the error message.

- An email adress with SMTP survice
- supervisor

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
   supervisord -c supervisor.conf
   cd ..
   supervisord -c celery.conf
   supervisord -c oj.conf
   ```
