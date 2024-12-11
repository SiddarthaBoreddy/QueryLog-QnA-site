from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape
from datetime import datetime, timedelta
from collections import Counter
import re
import nltk
from nltk.corpus import stopwords
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps
import os
from werkzeug.utils import secure_filename
import matplotlib.pyplot
matplotlib.use('Agg')
import matplotlib.pyplot as plt 
import numpy as np
from flask_socketio import SocketIO, join_room, leave_room, emit

app = Flask(__name__)
app.secret_key = "a34b1c19f16e8c10e9dbb2c61e435c3e"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://sboreddy:yourpassword@localhost/cs595'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a34b1c19f16e8c10e9dbb2c61e435c3e'
socketio = SocketIO(app)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'signin' 

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.before_request
def require_login():
    public_endpoints = ['signin', 'signup', 'static']
    if 'user_id' not in session and request.endpoint not in public_endpoints:
        return redirect(url_for('signin'))
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout after 30 minutes
@app.before_request
def make_session_permanent():
    session.permanent = True
# Models

room_invites = db.Table(
    'room_invites',
    db.Column('room_id', db.Integer, db.ForeignKey('room.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='room', cascade="all, delete-orphan")
    invited_users = db.relationship('User', secondary=room_invites, backref='invited_rooms')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='questions') 

    # Relationships
    comments = db.relationship('Comment', backref='parent_question', lazy=True, cascade="all, delete-orphan")
    answers = db.relationship('Answer', backref='parent_question', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', backref='related_question', lazy=True, cascade="all, delete-orphan")

class Answer(db.Model):
    __tablename__ = 'answer'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer_text = db.Column(db.String(500), nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    user = db.relationship('User', backref='answers')

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    comment_text = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    user = db.relationship('User', backref='comments')
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    parent_comment = db.relationship('Comment', remote_side=[id], backref=db.backref('replies', lazy=True))

class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Subcategory(db.Model):
    __tablename__ = 'subcategory'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('subcategories', lazy=True))

class LiveSession(db.Model):
    __tablename__ = 'live_session'
    __table_args__ = {'extend_existing': True}  # Allows modifications to the existing table

    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(255), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    zoom_link = db.Column(db.String(255), nullable=False)


class AnswerVote(db.Model):
    __tablename__ = 'answer_votes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('answer.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  # 'upvote' or 'downvote'

    user = db.relationship('User', backref=db.backref('answer_votes', lazy=True))
    answer = db.relationship('Answer', backref=db.backref('votes', lazy=True))

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(255), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    question = db.relationship('Question', backref='related_notifications')

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    job_title = db.Column(db.String(100), nullable=False)
    technology = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200), default='/static/default-user.png') 
    bio = db.Column(db.Text, nullable=True)  
    skills = db.Column(db.Text, nullable=True)  
    

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('feed'))  
    return redirect(url_for('signin'))

@app.route('/feed', methods=['GET', 'POST'])
def feed():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    filter_type = request.args.get('filter', 'newest')
    category_id = request.args.get('category')
    subcategory_id = request.args.get('subcategory')

    query = Question.query

    if filter_type == 'newest':
        query = query.order_by(Question.created_at.desc())
    elif filter_type == 'answers':
        query = (
            query.join(Answer)
            .group_by(Question.id)
            .having(db.func.count(Answer.id) > 0)
            .order_by(Question.created_at.desc())
        )
    elif filter_type == 'unanswered':
        query = (
            query.outerjoin(Answer)
            .group_by(Question.id)
            .having(db.func.count(Answer.id) == 0)
            .order_by(Question.created_at.desc())
        )

    # Apply category and subcategory filters
    if category_id:
        query = query.filter(Question.category == category_id)
    if subcategory_id:
        query = query.filter(Question.subcategory == subcategory_id)

    # Execute query to fetch questions
    questions = query.all()

    # Handle POST requests for answering or commenting
    if request.method == 'POST':
        question_id = request.form.get('question_id')
        action = request.form.get('action')

        if action == 'answer':
            answer_text = request.form.get('answer')
            new_answer = Answer(question_id=question_id, answer_text=answer_text, user_id=session['user_id'])
            db.session.add(new_answer)
            db.session.commit()
        elif action == 'comment':
            comment_text = request.form.get('comment')
            new_comment = Comment(question_id=question_id, comment_text=comment_text, user_id=session['user_id'])
            db.session.add(new_comment)
            db.session.commit()

        # Redirect to the feed while preserving the current filter
        return redirect(url_for('feed', filter=filter_type, category=category_id, subcategory=subcategory_id))

    # Extract keywords for hashtags
    one_week_ago = datetime.now() - timedelta(days=7)
    recent_questions = Question.query.filter(Question.created_at >= one_week_ago).all()
    nltk.download('stopwords')
    stop_words = set(stopwords.words('english'))
    all_keywords = [
        word.lower()
        for question in recent_questions
        for word in re.findall(r'\b\w+\b', question.question_text)
        if word.lower() not in stop_words and len(word) > 3
    ]
    keyword_counts = Counter(all_keywords)
    top_keywords = [f"#{keyword}" for keyword, _ in keyword_counts.most_common(5)]

    # Fetch categories, subcategories, and live sessions
    if category_id:
        query = query.filter(Question.category == category_id)
    if subcategory_id:
        query = query.filter(Question.subcategory == subcategory_id)
    categories = Category.query.all()
    for category in categories:
        category.subcategories = sorted(category.subcategories, key=lambda subcat: subcat.name.lower())
    categories = Category.query.all()
    subcategories = Subcategory.query.all()
    live_sessions = LiveSession.query.order_by(LiveSession.date, LiveSession.time).all()

    return render_template(
        'feed.html',
        questions=questions,
        categories=categories,
        subcategories=subcategories,
        filter_type=filter_type,
        top_keywords=top_keywords,
        live_sessions=live_sessions
    )

@app.route('/ask', methods=['GET', 'POST'])
def ask_question():
    if 'user_id' not in session:  # Ensure user is logged in
        flash("You need to be logged in to ask a question.", "error")
        return redirect(url_for('signin'))
    
    user_id = session['user_id']
    if request.method == 'POST':
        title = request.form.get('title')
        question_text = request.form.get('question')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        if title.strip() and question_text.strip():
            new_question = Question(
                title=title,
                question_text=question_text,
                category=category,
                subcategory=subcategory,
                user_id=user_id  # Simulating user ID for now
            )
            db.session.add(new_question)
            db.session.commit()
            flash("Question Submitted Successfully", "success")
            return redirect(url_for('ask_question'))
    categories = Category.query.all()
    subcategories = Subcategory.query.all()
    return render_template('ask_question.html', categories=categories, subcategories=subcategories)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session['user_id']  # Retrieve logged-in user's ID from session
    if not user_id:
        flash('Please log in to view your profile.', 'error')
        return redirect(url_for('signin'))
    user = User.query.get_or_404(user_id)  # Fetch user from database
    if request.method == 'POST':
        action = request.form.get('action')
        question_id = request.form.get('question_id')
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                user.profile_picture = f'/static/uploads/{filename}'
            else:
                flash('Invalid file type. Please upload PNG, JPG, or JPEG.', 'error')
        if 'bio' in request.form:
            user.bio = request.form.get('bio', '')
            print("Updated Bio:", user.bio)  
        if 'skills' in request.form:
            user.skills = request.form.get('skills', '')
            print("Updated Skills:", user.skills)  
        db.session.commit()

        if action == 'delete':
            question = Question.query.get_or_404(question_id)
            if question.user_id == user_id:  # Ensure the user owns the question
                Comment.query.filter_by(question_id=question.id).delete()
                Answer.query.filter_by(question_id=question.id).delete()
                db.session.delete(question)
                db.session.commit()
                flash('Question deleted successfully.', 'success')
            else:
                flash('You are not authorized to delete this question.', 'error')
        elif action == 'edit':
            return redirect(url_for('edit_question', question_id=question_id))
    
        # flash('Profile updated successfully!', 'success')
            
        return redirect(url_for('profile'))
    
    print("Session User ID:", session.get('user_id'))
    print("User Data:", user.bio, user.skills)  # Debugging
    questions_count = Question.query.filter_by(user_id=user_id).count()
    answers_count = Answer.query.filter_by(user_id=user_id).count()
    upvotes_count = db.session.query(db.func.sum(Answer.upvotes)).filter_by(user_id=user_id).scalar() or 0
    downvotes_count = db.session.query(db.func.sum(Answer.downvotes)).filter_by(user_id=user_id).scalar() or 0

    # Generate graph
    labels = ['Questions', 'Answers', 'Upvotes', 'Downvotes']
    values = [questions_count, answers_count, upvotes_count, downvotes_count]
    x = np.arange(len(labels))

    plt.figure(figsize=(10, 5))
    bar_width = 0.1  # Make bars thinner
    bars = plt.bar(
        x, values, width=bar_width, 
        color=['#007bff', '#28a745', '#ffc107', '#dc3545'], 
        edgecolor='black', 
        linewidth=1.2,
        alpha=0.9  # Slight transparency for a modern look
    )

    # Add value annotations on bars
    for bar in bars:
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.2,
            int(bar.get_height()),
            ha='center',
            va='bottom',
            fontsize=12,
            color='#333',
            fontweight='bold',
        )

    # Graph styling
    plt.title(f"{user.first_name}'s Contributions", fontsize=18, fontweight='bold', color='#333')
    plt.ylabel('Count', fontsize=14, color='#555')
    plt.xticks(x, labels, fontsize=12, color='#333', fontweight='bold')
    plt.yticks(fontsize=12, color='#555')
    plt.grid(axis='y', linestyle='--', linewidth=0.5, alpha=0.7)  # Subtle grid lines
    plt.box(False)  # Remove border box for a cleaner look
    plt.tight_layout()

    # Save the graph
    graph_path = 'static/user_contributions.png'
    plt.savefig(graph_path, dpi=300)
    plt.close()

    questions = Question.query.filter_by(user_id=user_id).all()
    return render_template('profile.html', user=user, questions=questions, graph_path=graph_path)

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:  # Check if the user is logged in
        flash('You must be logged in to vote.', 'error')
        return redirect(url_for('signin'))
    answer_id = request.form.get('answer_id')
    vote_type = request.form.get('vote_type')  # 'upvote' or 'downvote'
    user_id = session['user_id']

    if not answer_id or not vote_type:
        flash('Invalid vote request.', 'error')
        return redirect(request.referrer or url_for('feed'))

    existing_vote = AnswerVote.query.filter_by(user_id=user_id, answer_id=answer_id).first()

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            # If the user is trying to vote the same way again, remove the vote
            db.session.delete(existing_vote)
            if vote_type == 'upvote':
                Answer.query.get(answer_id).upvotes -= 1
            elif vote_type == 'downvote':
                Answer.query.get(answer_id).downvotes -= 1
            db.session.commit()
            
        else:
            # If the user is switching their vote, update the vote
            existing_vote.vote_type = vote_type
            if vote_type == 'upvote':
                Answer.query.get(answer_id).upvotes += 1
                Answer.query.get(answer_id).downvotes -= 1
            elif vote_type == 'downvote':
                Answer.query.get(answer_id).downvotes += 1
                Answer.query.get(answer_id).upvotes -= 1
            db.session.commit()
            
    else:
        # If the user hasn't voted yet, create a new vote
        new_vote = AnswerVote(user_id=user_id, answer_id=answer_id, vote_type=vote_type)
        db.session.add(new_vote)
        if vote_type == 'upvote':
            Answer.query.get(answer_id).upvotes += 1
        elif vote_type == 'downvote':
            Answer.query.get(answer_id).downvotes += 1
        db.session.commit()
        
    return redirect(url_for('show_answers', question_id=Answer.query.get(answer_id).question_id))

@app.route('/answers/<int:question_id>', methods=['GET', 'POST'])
def show_answers(question_id):
    question = Question.query.get_or_404(question_id)
    
    # Sort answers by upvotes in descending order
    answers = Answer.query.filter_by(question_id=question_id).order_by(Answer.upvotes.desc()).all()


    user_id = session.get('user_id')
    user_votes = {}
    if user_id:
        user_votes = {
            vote.answer_id: vote.vote_type
            for vote in AnswerVote.query.filter_by(user_id=user_id).all()
        }

    if request.method == 'POST':
        action = request.form.get('action')
        answer_id = request.form.get('answer_id')
        answer = Answer.query.get_or_404(answer_id)

        if action == 'upvote':
            answer.upvotes += 1
        elif action == 'downvote':
            answer.downvotes += 1

        db.session.commit()
        return redirect(url_for('show_answers', question_id=question_id))
    open_comments = request.args.get('open_comments')

    return render_template('question_answers.html', question=question, answers=answers, user_votes=user_votes,open_comments=open_comments)


@app.template_filter('escapejs')
def escapejs_filter(value):
    return escape(value).replace("'", "\\'").replace('"', '\\"')

app.jinja_env.filters['escapejs'] = escapejs_filter

@app.route('/post_comment', methods=['POST'])
def post_comment():
    question_id = request.form.get('question_id')
    comment_text = request.form.get('comment')
    user_id = session.get('user_id')
    if 'user_id' not in session:
        flash("Please log in to comment.", "error")
        return redirect(url_for('signin'))

    if comment_text.strip():
        new_comment = Comment(question_id=question_id, comment_text=comment_text, user_id=user_id)
        db.session.add(new_comment)
        db.session.commit()

        question = Question.query.get(question_id)
        if question and question.user_id != user_id:
            notification = Notification(
                user_id=question.user_id,
                content=f"{session['first_name']} commented on your question '{question.title}'",
                question_id=question_id
            )
            db.session.add(notification)
            db.session.commit()
            print(f"Notification created: {notification.content}")  # Debug print
            print(f"Notification for user_id: {question.user_id}") 
        # flash("", "success")
    else:
        flash("Comment cannot be empty.", "error")
    return redirect(url_for('feed', open_comments=question_id))

@app.route('/post_answer', methods=['POST'])
def post_answer():
    question_id = request.form.get('question_id')
    answer_text = request.form.get('answer')
    user_id = session.get('user_id')

    if 'user_id' not in session:
        flash("Please log in to answer.", "error")
        return redirect(url_for('signin'))

    if answer_text.strip():
        new_answer = Answer(
            question_id=question_id,
            answer_text=answer_text,
            user_id=user_id  # Use logged-in user's ID
        )
        db.session.add(new_answer)
        db.session.commit()
        question = Question.query.get(question_id)
        if question and question.user_id != user_id:
            notification = Notification(
                user_id=question.user_id,
                content=f"{session['first_name']} answered your question '{question.title}'",
                question_id=question_id
            )
            db.session.add(notification)
            db.session.commit()
        # flash("Answer posted successfully!", "success")
    else:
        flash("Answer cannot be empty.", "error")
    return redirect(url_for('show_answers', question_id=question_id))

@app.route('/schedule_live_session', methods=['GET', 'POST'])
def schedule_live_session():
    if request.method == 'POST':
        topic = request.form.get('topic')
        date = request.form.get('date')
        time = request.form.get('time')
        zoom_link = request.form.get('zoom_link')

        new_session = LiveSession(topic=topic, date=date, time=time, zoom_link=zoom_link)
        db.session.add(new_session)
        db.session.commit()
        # flash("Live session scheduled successfully!", "success")
        return redirect(url_for('feed'))

    return render_template('schedule_live_session.html')


@app.route('/live_session/<int:session_id>')
def live_session_details(session_id):
    live_session = LiveSession.query.get_or_404(session_id)  # Retrieve session by ID or 404
    print(live_session)  # Debug: Print session object
    return render_template('live_session_details.html', live_session=live_session)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        job_title = request.form.get('job_title')
        technology = request.form.get('technology')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            job_title=job_title,
            technology=technology,
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.', 'success')
        return redirect(url_for('signin'))

    return render_template('signup.html')
def authenticate_user(email, password):
    """
    Authenticate the user by email and password.
    """
    user = User.query.filter_by(email=email).first()  # Query the user by email
    if user and user.check_password(password):  # Verify the password
        return user
    return None
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = authenticate_user(email, password)  # Use the newly defined function
        if user:
            session['user_id'] = user.id
            session['first_name'] = user.first_name
            flash('Login successful!', 'success')
            return redirect(url_for('feed'))  # Redirect to feed after successful login

        flash('Invalid email or password.', 'error')  # Show error message for invalid credentials

    return render_template('signin.html')


@app.route('/reply_to_comment', methods=['POST'])
def reply_to_comment():
    parent_comment_id = request.form.get('parent_comment_id')
    question_id = request.form.get('question_id')
    reply_text = request.form.get('reply')

    if 'user_id' not in session:
        flash("You must be logged in to reply.", "error")
        return redirect(url_for('signin'))

    if not parent_comment_id or not reply_text.strip():
        flash('Reply cannot be empty.', 'error')
        return redirect(url_for('show_answers', question_id=question_id, open_comments=parent_comment_id))
    
    parent_comment = Comment.query.get(parent_comment_id)
    question = Question.query.get(question_id)
    if not parent_comment or not question:
        flash('Invalid comment or question.', 'error')
        return redirect(url_for('show_answers', question_id=question_id, open_comments=parent_comment_id))


    new_reply = Comment(
        question_id=question_id,
        comment_text=reply_text,
        parent_comment_id=parent_comment_id,
        user_id=session['user_id'] # Assuming the user is logged in
    )
    db.session.add(new_reply)
    db.session.commit()

    # flash('Reply posted successfully!', 'success')
    return redirect(url_for('feed', open_comments=question_id))


@app.route('/signout')
def signout():
    if 'user_id' in session:  # Ensure user is logged in
        session.clear()  # Clear all session data
        flash('You have been logged out.', 'success')
    else:
        flash('You are not logged in.', 'error')  # Handle case where user tries to access without login
    return redirect(url_for('signin'))  # Redirect to the sign-in page

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        flash("Please log in to view notifications.", "error")
        return redirect(url_for('signin'))
    
    user_id = session['user_id']
    user_notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

# @app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
# def mark_notification_read(notification_id):
#     if 'user_id' not in session:
#         flash("Please log in to view notifications.", "error")
#         return redirect(url_for('signin'))
    
#     notification = Notification.query.get(notification_id)
#     if notification and notification.user_id == session['user_id']:
#         notification.is_read = True
#         db.session.commit()
#     return redirect(url_for('notifications'))

@app.context_processor
def inject_unread_notifications_count():
    user_id = session.get('user_id')
    if user_id:
        unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        print(f"Unread notifications for user {user_id}: {unread_count}")  # Debug print
        return {'unread_notifications_count': unread_count}
    print("No user logged in for notifications.")  # Debug print
    return {'unread_notifications_count': 0}

@app.route('/test_notification', methods=['GET'])
def test_notification():
    user_id = session.get('user_id')
    if user_id:
        notification = Notification(
            user_id=user_id,
            content="Test notification",
            question_id=1  # Replace with a valid question ID
        )
        db.session.add(notification)
        db.session.commit()
        return "Test notification created!"
    return "User not logged in."

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    
    # Check if the current user is the owner of the question
    if question.user_id != session['user_id']:
        flash('You are not authorized to delete this question.', 'error')
        return redirect(url_for('profile'))
    
    # Delete related notifications
    Notification.query.filter_by(question_id=question_id).delete()
    
    # Delete the question
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully.', 'success')
    return redirect(url_for('profile'))


@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)

    if 'user_id' not in session or question.user_id != session['user_id']:
        flash('You are not authorized to edit this question.', 'error')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        question.title = request.form.get('title')
        question.question_text = request.form.get('question_text')
        question.category = request.form.get('category')
        question.subcategory = request.form.get('subcategory')

        db.session.commit()
        flash('Question updated successfully.', 'success')
        return redirect(url_for('profile'))

    categories = Category.query.all()
    subcategories = Subcategory.query.all()
    return render_template(
        'edit_question.html', 
        question=question, 
        categories=categories, 
        subcategories=subcategories
    )


@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    if 'user_id' not in session:
        flash("Please log in to view notifications.", "error")
        return redirect(url_for('signin'))
    
    notification = Notification.query.get(notification_id)
    if notification and notification.user_id == session['user_id']:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_all_notifications_read', methods=['POST'])
def mark_all_notifications_read():
    if 'user_id' not in session:
        flash("Please log in to view notifications.", "error")
        return redirect(url_for('signin'))
    
    Notification.query.filter_by(user_id=session['user_id'], is_read=False).update({'is_read': True})
    db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room_name = request.form.get('room_name')
    is_private = request.form.get('is_private') == 'true'
    room = Room(name=room_name, is_private=is_private, created_by=session['user_id'])
    db.session.add(room)
    db.session.commit()
    flash('Room created successfully!', 'success')
    return redirect(url_for('rooms'))

@app.route('/rooms')
@login_required
def rooms():
    user_id = session['user_id']
    rooms = Room.query.filter(
        (Room.is_private == False) | (Room.created_by == user_id)
    ).all()
    print(f"Rooms visible to user {user_id}: {[room.name for room in rooms]}")
    return render_template('rooms.html', rooms=rooms)

@app.route('/room/<int:room_id>')
@login_required
def room(room_id):
    room = Room.query.get_or_404(room_id)
    
    print(f"Room ID: {room_id}, Room Name: {room.name}, Is Private: {room.is_private}, Created By: {room.created_by}")
    print(f"Current User ID: {session['user_id']}")

    if room.is_private and session['user_id'] not in [user.id for user in room.invited_users] and session['user_id'] != room.created_by:
        flash("You don't have permission to access this private room.", "error")
        return redirect(url_for('rooms'))
    
    return render_template('room.html', room=room)

@socketio.on('join')
def handle_join(data):
    room_id = data['room_id']
    user_id = session['user_id']
    room = Room.query.get(room_id)
    
    if room.is_private and room.created_by != user_id:
        emit('error', {'message': 'Unauthorized to join this private room.'})
        return
    
    join_room(room_id)
    emit('message', {'content': f'{session["first_name"]} has joined the room.'}, to=room_id)

@socketio.on('message')
def handle_message(data):
    room_id = data['room_id']
    message = data['message']
    user_id = session['user_id']

    new_message = Message(room_id=room_id, user_id=user_id, content=message)
    db.session.add(new_message)
    db.session.commit()

    emit('message', {'content': message, 'user': session['first_name']}, to=room_id)

@app.route('/room/<int:room_id>/invite', methods=['POST'])
@login_required
def invite_to_room(room_id):
    room = Room.query.get_or_404(room_id)
    if room.created_by != session['user_id']:
        flash("You don't have permission to invite users to this room.", "error")
        return redirect(url_for('room', room_id=room_id))

    user_email = request.form.get('user_email')
    user = User.query.filter_by(email=user_email).first()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('room', room_id=room_id))

    if user in room.invited_users:
        flash("User is already invited.", "info")
        return redirect(url_for('room', room_id=room_id))

    room.invited_users.append(user)
    db.session.commit()

    flash(f"{user.first_name} has been invited to the room.", "success")
    return redirect(url_for('room', room_id=room_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)