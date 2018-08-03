# vim: sw=4:ts=4:et

from . import login_manager, db
from saq.database import User

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))
    #return User.query.get(int(user_id))
