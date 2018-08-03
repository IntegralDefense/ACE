# vim: sw=4:ts=4:et
from flask import Blueprint
cloudphish = Blueprint('cloudphish', __name__)
from . import views
