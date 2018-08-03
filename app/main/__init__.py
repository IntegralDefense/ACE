# vim: sw=4:ts=4:et
from flask import Blueprint
main = Blueprint('main', __name__)
from . import views, errors
