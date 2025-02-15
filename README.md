# NumericalOJ
An online-judge system for MATLAB, Baltamatica or Octave.

### Requirement

- Ubuntu 22.04
- One of them: MATLAB, Baltamatica, Octave
  - **Note:** The default setting is Ovtave. If you want others, you should edit `judger/app.py`. I'm sure you will know how to edit once you see the code.
- MySQL
- Redis
- Python3
- Some Python packages which can be installed by pip
- An email adress with SMTP survice

### Deployment

Firstly, make your MySQL database as the initial structure. And set your SMRT service well. After that, complete the configures in `config.py`.

Now You need 3 terminals. The first:

```bash
cd judger
python3 app.py
```

The second:

```bash
celery -A oj.celery worker --loglevel=info
```

The third:

```bash
python3 oj.py
```

You can also hang the processes with `supervisor`.

### MySQL Initial Structure

Database: `myojdb`

Tables:
```
+------------------------+
| Tables_in_myojdb       |
+------------------------+
| ac_record              |
| class_table            |
| max_score              |
| problems               |
| submissions            |
| users                  |
| verification_codes     |
+------------------------+
```

Table `ac_record` (This table will have more columns automatically when new problems added):
```
+--------+------------+------+-----+---------+-------+
| Field  | Type       | Null | Key | Default | Extra |
+--------+------------+------+-----+---------+-------+
| userid | int        | NO   | PRI | NULL    |       |
+--------+------------+------+-----+---------+-------+
```

Table `class_table`
```
+-----------+--------------+------+-----+---------+-------+
| Field     | Type         | Null | Key | Default | Extra |
+-----------+--------------+------+-----+---------+-------+
| class_en  | varchar(255) | NO   | PRI | NULL    |       |
| class_cn  | varchar(255) | YES  |     | NULL    |       |
| class_cnt | int          | YES  |     | 0       |       |
+-----------+--------------+------+-----+---------+-------+
```

Table `max_score` (This table will have more columns automatically when new problems added):
```
+----------+------+------+-----+---------+-------+
| Field    | Type | Null | Key | Default | Extra |
+----------+------+------+-----+---------+-------+
| userid   | int  | NO   | PRI | NULL    |       |
| class_en | text | YES  |     | NULL    |       |
+----------+------+------+-----+---------+-------+
```

Table `problems`
```
+----------------+--------------+------+-----+---------+----------------+
| Field          | Type         | Null | Key | Default | Extra          |
+----------------+--------------+------+-----+---------+----------------+
| id             | int          | NO   | PRI | NULL    | auto_increment |
| title          | varchar(255) | NO   |     | NULL    |                |
| content        | text         | NO   |     | NULL    |                |
| initial_code   | text         | NO   |     | NULL    |                |
| testdata       | longtext     | YES  |     | NULL    |                |
| cnt            | int          | YES  |     | 0       |                |
| forbidden_func | text         | YES  |     | NULL    |                |
+----------------+--------------+------+-----+---------+----------------+
```

Table `submissions`
```
+---------------+-------------+------+-----+-------------------+-------------------+
| Field         | Type        | Null | Key | Default           | Extra             |
+---------------+-------------+------+-----+-------------------+-------------------+
| id            | int         | NO   | PRI | NULL              | auto_increment    |
| problem_id    | int         | NO   |     | NULL              |                   |
| username      | varchar(50) | NO   |     | NULL              |                   |
| code          | text        | NO   |     | NULL              |                   |
| score         | int         | NO   |     | NULL              |                   |
| test_points   | text        | YES  |     | NULL              |                   |
| created_at    | datetime    | NO   |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
| status        | text        | NO   |     | NULL              |                   |
| problem_title | text        | YES  |     | NULL              |                   |
+---------------+-------------+------+-----+-------------------+-------------------+
```

Table `users`
```
+---------------+-------------+------+-----+---------+----------------+
| Field         | Type        | Null | Key | Default | Extra          |
+---------------+-------------+------+-----+---------+----------------+
| id            | int         | NO   | PRI | NULL    | auto_increment |
| username      | varchar(50) | NO   | UNI | NULL    |                |
| password_hash | char(64)    | NO   |     | NULL    |                |
| is_admin      | tinyint(1)  | NO   |     | 0       |                |
| email         | text        | YES  |     | NULL    |                |
| class         | text        | YES  |     | NULL    |                |
| class_cn      | text        | YES  |     | NULL    |                |
+---------------+-------------+------+-----+---------+----------------+
```

Table `verification_codes`
```
+------------+--------------+------+-----+---------+-------+
| Field      | Type         | Null | Key | Default | Extra |
+------------+--------------+------+-----+---------+-------+
| email      | varchar(255) | NO   | PRI | NULL    |       |
| code       | varchar(6)   | NO   |     | NULL    |       |
| expires_at | datetime     | NO   |     | NULL    |       |
+------------+--------------+------+-----+---------+-------+
```
