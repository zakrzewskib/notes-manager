import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db
from app import Note 

new = Note(content="Note that belong to user 2", user_id=2, isEncrypted=False)

db.session.add(new)
db.session.commit()