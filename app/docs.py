"""Dokumenty – zasób chroniony uprawnieniami ról (RBAC)."""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .auth import permission_required
from .db import get_db
from .utils import now, to_iso

bp = Blueprint("docs", __name__, url_prefix="/docs")


def _get_doc(doc_id):
    """Pobiera dokument z nazwiskiem autora albo zwraca 404."""
    doc = get_db().execute(
        "SELECT d.*, u.full_name AS owner_name FROM documents d "
        "LEFT JOIN users u ON u.id = d.owner_id WHERE d.id = ?",
        (doc_id,),
    ).fetchone()
    if doc is None:
        abort(404)
    return doc


@bp.get("/")
@permission_required("docs.read_public")           # Gość i Pracownik
def index():
    """Lista dokumentów. Gość dostaje tylko publiczne."""
    query = ("SELECT d.*, u.full_name AS owner_name FROM documents d "
             "LEFT JOIN users u ON u.id = d.owner_id")
    if "docs.read_all" not in g.permissions:        # bez read_all -> filtr na publiczne
        query += " WHERE d.is_public = 1"
    docs = get_db().execute(query + " ORDER BY d.updated_at DESC").fetchall()
    return render_template("docs/list.html", docs=docs)


@bp.get("/<int:doc_id>")
@permission_required("docs.read_public")
def view(doc_id):
    """Podgląd dokumentu. Wewnętrzny wymaga docs.read_all."""
    doc = _get_doc(doc_id)
    if not doc["is_public"] and "docs.read_all" not in g.permissions:
        abort(403)                                  # Gość wpisał id dokumentu wewnętrznego
    return render_template("docs/view.html", doc=doc)


@bp.route("/new", methods=["GET", "POST"])
@permission_required("docs.create")                # tylko Pracownik
def new():
    return _form(None)


@bp.route("/<int:doc_id>/edit", methods=["GET", "POST"])
@permission_required("docs.edit_own")              # tylko Pracownik...
def edit(doc_id):
    doc = _get_doc(doc_id)
    if doc["owner_id"] != g.user["id"]:             # ...i tylko WŁASNE dokumenty
        abort(403)                                  # kontrola na poziomie obiektu
    return _form(doc)


def _form(doc):
    """Wspólny formularz dla nowego i edytowanego dokumentu."""
    errors = []
    form = {
        "title": doc["title"] if doc else "",
        "body": doc["body"] if doc else "",
        "is_public": bool(doc["is_public"]) if doc else False,
    }
    if request.method == "POST":
        form = {
            "title": request.form.get("title", "").strip(),
            "body": request.form.get("body", "").strip(),
            "is_public": request.form.get("is_public") == "on",   # checkbox
        }
        if not form["title"] or not form["body"]:
            errors.append("Tytuł i treść są wymagane.")
        if not errors:
            db = get_db()
            timestamp = to_iso(now())
            if doc is None:                         # nowy dokument
                cur = db.execute(
                    "INSERT INTO documents (title, body, is_public, owner_id, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (form["title"], form["body"], int(form["is_public"]), g.user["id"], timestamp, timestamp),
                )
                doc_id = cur.lastrowid
            else:                                   # edycja istniejącego
                db.execute(
                    "UPDATE documents SET title = ?, body = ?, is_public = ?, updated_at = ? WHERE id = ?",
                    (form["title"], form["body"], int(form["is_public"]), timestamp, doc["id"]),
                )
                doc_id = doc["id"]
            db.commit()
            flash("Zapisano dokument.", "success")
            return redirect(url_for("docs.view", doc_id=doc_id))
    return render_template("docs/form.html", doc=doc, form=form, errors=errors)