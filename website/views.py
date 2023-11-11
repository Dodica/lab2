from flask import Blueprint, render_template, request, flash, jsonify, current_app
from flask_login import login_required, current_user
from .models import Note
from . import db
import json
import sqlite3

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST': 
        note = request.form.get('note')
        show_password_rules = 'showPasswordRules' in request.form

        if not show_password_rules:
            if len(note) < 1:
                flash('Note is too short!', category='error') 
            else:
                new_note = Note(data=note, user_id=current_user.id)
                db.session.add(new_note)
                db.session.commit()
                flash('Note added!', category='success')
        else:
            conn = sqlite3.connect('instance/database.db')
            cursor = conn.cursor()
            data = note
            user_id = current_user.id
            insert_query = "INSERT INTO note (data, user_id) VALUES (?, ?)"
            cursor.execute(insert_query, (data, user_id))
            conn.commit()
            conn.close()

    return render_template("home.html", user=current_user)


@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})
