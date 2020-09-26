from flask import Flask, redirect, render_template, request, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from wtforms.validators import Email, InputRequired, EqualTo, Length
from pymongo import MongoClient
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required
from bson.objectid import ObjectId
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = "pass_API_log"
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'log_pg'


class Cadastroform(FlaskForm):
    userName = StringField('Nome de usuario:', validators = [InputRequired(), Length(3, 20, 'O nome deve ter entre 3 e 20 caracteres.')])
    newEmail = StringField('E-mail:', validators = [InputRequired(), Email('Insira um endereço de E-mail valido.')])
    mailConfirm = StringField('Confirme o E-mail:', validators = [InputRequired(), EqualTo('newEmail', 'Ambos os campos devem ser iguais.')])
    newPass = PasswordField('Senha:', validators = [InputRequired(), Length(5, 15, 'A senha deve ter entre 5 e 15 caracteres.')])
    passConfirm  = PasswordField('Confirme a senha:', validators = [InputRequired(), EqualTo('newPass', 'Ambos os campos devem ser iguais.')])
    submit = SubmitField('Submit')


class Loginform(FlaskForm):
    userName = StringField('userName', validators = [InputRequired()])
    Email = StringField('E-mail: ', validators = [InputRequired(), Email('Insira um endereço de E-mail valido.')])
    Password = PasswordField('Senha:', validators = [InputRequired(), Length(5, 15, 'A senha deve ter entre 5 e 15 caracteres.')])
    submit = SubmitField('Submit')
        
    
class Appform(FlaskForm):
    Name = StringField('userName', validators = [InputRequired()])
    Question = StringField('userName', validators = [InputRequired()])

class User(UserMixin):
    
    def __init__(self, data):
        self._id = data['_id']
        self.Nome = data['Nome']
        self.Email = data['Email']
        self.Senha = data['Senha']
        
    @property
    def is_authenticated(self):
        return True
        
    @property
    def is_active(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self._id
    
    
@login_manager.user_loader
def load_user(user_id):
    client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
    db = client.db
    u = db['users'].find_one({"Name": user_id})
    if not u:
        return None
    return User(u)  
    
     
     
     
     
     
@app.route("/")
def inicial():
        
    return render_template("pg_init.html")
    

@app.route("/Login", methods=['GET', 'POST'])
def log_pg():
    
    form = Loginform()

    if form.validate_on_submit:
        client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
        db = client.db
        check = db['users'].find_one({ 'Email': form.Email.data})
        
        if check:
        
            if check_password_hash(check['Senha'], form.Password.data):
            
                
                user = User(check)
                login_user(user)
                
                client.close()
                return redirect("/main")
                
            else:
                client.close()
                flash('senha incorreta')
                
        else:
            client.close()
            client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
            db = client.db
            check2 = db['colaborators'].find_one({ 'Email': form.Email.data})
            
            if check2:
        
                if check_password_hash(check2['Senha'], form.Password.data):
                    user = User(check)
                    login_user(user)
                
                    client.close()
                    return redirect("/main")
                    
                else:
                    flash('Email e/ou senha incorreta')
            
            
        
    return render_template("auth/pg_log_bootstrap.html", form=form)


''' falta testar daqui pra baixo'''
@app.route("/userSingUp", methods=['GET', 'POST'])
def userSingUp():

    form = Cadastroform()
    
    if form.validate_on_submit():
    
        client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
        db = client.db
        checkEmail = db['users'].find_one({ 'Email': form.newEmail.data})
        
        if checkEmail is None:
        
            passHash = generate_password_hash(form.newPass.data)
            db['users'].insert_one(
                {
                    "_id": uuid.uuid4().hex,
                    "Email": form.newEmail.data,
                    "Nome": form.userName.data,
                    "Senha": passHash
                }
            )
            client.close()
            return redirect("/Login")
        else:    
            flash('E-mail ja cadastrado')
    
    return render_template("pg_cad_users.html", form=form)


@app.route("/colabSingUp", methods=['GET', 'POST'])
def colaboratorSingUp():

    form = Cadastroform()
    
    if form.validate_on_submit():
       
        client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
        db = client.db
        checkEmail = db['colaborators'].find_one({ 'Email': form.newEmail.data})
        
        if checkEmail is None:
        
            passHash = generate_password_hash(form.newPass.data)
            db['colaborators'].insert_one(
                {   
                    "_id": uuid.uuid4().hex,
                    "Email": form.newEmail.data,
                    "Nome": form.userName.data,
                    "Senha": passHash
                }
            )
            client.close()
            return redirect("/Login")
        flash('E-mail ja cadastrado')
    
    return render_template("pg_cad_colab.html", form=form)
    

@app.route("/applicationSingUp", methods=['GET', 'POST'])
def appSingUp():

    form = Appform()
    
    if form.validate_on_submit():
       
        client = MongoClient("mongodb+srv://vtr363:1234@cluster0.d1wep.gcp.mongodb.net/test")
        db = client.db
        checkEmail = db['application'].find_one({ 'Nome': form.Name.data})
        
        if checkEmail is None:
        
            db.application.insert_one(
                {
                    "Nome": form.Name.data,
                    "key": Null,
                    "Key_status": 0,
                    "Question": Null
                }
            )
            client.close()
            return redirect("/Login")
        flash('E-mail ja cadastrado')
    
    return render_template("pg_cad_app.html", form=form)
    
    
@app.route("/main")
@login_required
def main_pg():
    
    
    
    return render_template("mainAPIpage.html")


if __name__ == "__main__":
    app.run(debug=True)
    