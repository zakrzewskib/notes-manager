from app import db
from app import Note 

new = Note(content="Another note", user_id=1)

db.session.add(new)
db.session.commit()