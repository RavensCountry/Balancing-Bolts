import sqlite3
conn = sqlite3.connect('backend/app.db')
c = conn.cursor()
rows = list(c.execute('select id,email,hashed_password from user'))
print(rows)
conn.close()
