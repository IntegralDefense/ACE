# vim: sw=4:ts=4:et
from flask import Blueprint
vt_hash_cache_bp = Blueprint('vt_hash_cache', __name__)
from . import views
