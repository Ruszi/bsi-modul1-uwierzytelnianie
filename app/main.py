"""Strona główna (pulpit) – dostępna tylko po zalogowaniu."""
from flask import Blueprint, render_template

from .auth import login_required

bp = Blueprint("main", __name__)


@bp.get("/")
@login_required                       # niezalogowany -> przekierowanie na /login
def index():
    return render_template("index.html")