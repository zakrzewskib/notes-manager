from app import db
from app import Note 

new_user = Note(content="Another note", user_id=2)

db.session.add(new_user)
db.session.commit()