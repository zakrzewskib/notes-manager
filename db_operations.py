from app import db
from app import Note 

new = Note(content="Another secret message 2", user_id=2, isEncrypted=False)

db.session.add(new)
db.session.commit()