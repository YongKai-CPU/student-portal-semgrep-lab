# Running the Student Portal in Kali

```bash
# 1. Database (MariaDB comes with Kali; install it if missing)
sudo apt install -y mariadb-server
sudo systemctl start mariadb
sudo mysql -e "CREATE DATABASE IF NOT EXISTS student_portal;
CREATE USER IF NOT EXISTS 'portal_user'@'localhost' IDENTIFIED BY 'ChangeMe123!';
GRANT ALL PRIVILEGES ON student_portal.* TO 'portal_user'@'localhost';
FLUSH PRIVILEGES;"

# 2. Python environment
cd ~/student_portal_lab_secure
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Create tables + demo users (you will be asked to choose their passwords)
export DB_PASSWORD='ChangeMe123!'
python init_db.py

# 4. Run
python app_secure.py
# open http://127.0.0.1:5000  -> log in as student1 or lecturer1
```

Every new terminal needs `source venv/bin/activate` and `export DB_PASSWORD='ChangeMe123!'` again before running the app.
