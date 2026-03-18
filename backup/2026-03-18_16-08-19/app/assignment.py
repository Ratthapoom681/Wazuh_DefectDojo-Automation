import sqlite3
import logging
from .config import DB_PATH

logger = logging.getLogger(__name__)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assignments
                 (group_name TEXT PRIMARY KEY, last_index INTEGER)''')
    conn.commit()
    conn.close()

def get_next_user(group_name: str, active_users: list[str]) -> str:
    if not active_users:
        return None
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT last_index FROM assignments WHERE group_name = ?", (group_name,))
    row = c.fetchone()
    
    if row is None:
        next_idx = 0
        c.execute("INSERT INTO assignments (group_name, last_index) VALUES (?, ?)", (group_name, next_idx))
    else:
        next_idx = (row[0] + 1) % len(active_users)
        c.execute("UPDATE assignments SET last_index = ? WHERE group_name = ?", (next_idx, group_name))
        
    conn.commit()
    conn.close()
    
    return active_users[next_idx]