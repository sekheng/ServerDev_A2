"""`main` is the top level module for your Flask application."""

# Import the Flask Framework
from flask import Flask, render_template, url_for, Response, redirect, make_response, request, jsonify, abort, session, escape
from google.appengine.ext import ndb
# import requests failed miserably!
import logging
import urllib2
import random
import requests
import os
import string
import json
from MyModel import *

app = Flask(__name__)
# Note: We don't need to call run() since our application is embedded within
# the App Engine WSGI application server.

# set the secret key.  keep this really secret:
app.secret_key = os.urandom(24)
#logger = logging.getLogger()
#logging.getLogger().setLevel(logging.DEBUG)

class UserConflict(Exception):
	status_code = 409
	def __init__(self, message, status_code=None, payload=None):
		Exception.__init__(self)
		self.message = message
		if status_code is not None:
			self.status_code = status_code
		self.payload = payload

@app.route('/')
def main():
    """Return a friendly HTTP greeting."""
    # assign a new id to the player if 
    signed_inFlag = False
    sign_in_Username = ''
    if 'user' in session:
        # if it is the admin, redirect it to the admin!
        if session['usertype'] == 'Admin':
            return admin_page()
        logging.info('Logged in as %s' % escape(session['user']))
        sign_in_Username = session['user']
        signed_inFlag = True
    else:
        session['user'] = ""
        session['score'] = 0
        logging.info("New user, %s" % (str(session)))
    game_list = get_all_games()
    return render_template('main.html', game_list = json.loads(game_list), signed_in = signed_inFlag, sign_in_name = sign_in_Username)

@app.route('/games', methods=['GET', 'DELETE'])
def get_all_games():
    logging.info("Getting all games")
    response_dict = {}
    if request.method == 'GET':
        # access all of the games!
        response_dict = []
        tableOfRandomWord = WordGame.query(WordGame.is_deleted == False)
        for randomword in tableOfRandomWord:
            respondWord = {'hint' : randomword.hint, 'word_length' : randomword.word_length, 'game_id' : str(randomword.key.id())}
            response_dict.append(respondWord)
    elif request.method == "DELETE":
        if 'user' not in session and session['usertype'] != 'Admin':
            response_dict['error'] = 'You do not have permission to perform this operation'
            abort(403)
        else:
            # get all of the words and delete it!
            AllNotDeletedWords = WordGame.query(WordGame.is_deleted == False)
            for notDeletedWord in AllNotDeletedWords:
                notDeletedWord.is_deleted = True
    else:
        response_dict['error'] = 'Method not allowed'
    return json.dumps(response_dict)

@app.route('/games/<string:game_id>', methods=['GET', 'DELETE'])
def games(game_id):
    logging.info("Getting specific game: " + game_id)
    game_property = {}
    wordDatabase = WordGame.query(WordGame.game_id == game_id)
    specificWord = wordDatabase.get()
    if specificWord is None:
        game_property['error'] = 'Game not found'
    else:
        if 'user' not in session:
            abort(403)
            game_property['error'] = 'You do not have permission to perform this operation'
        elif request.method == 'GET':
            game_property['hint'] = specificWord.hint
            game_property['word_length'] = specificWord.word_length
            game_property['game_id'] = specificWord.game_id
            return render_template('game.html', game_property = game_property)
        elif request.method == 'DELETE':
            specificWord.is_deleted = True
            specificWord.put()
            game_property['message'] = 'Game was deleted'
        else:
            game_property['error'] = "Method not allowed"
            abort(405)
    return game_property

@app.route('/games/<int:word_length>', methods=['GET'])
def ongoing_games(word_length):
    logging.info("Getting words with specific word_length!")
    response_dict = {}
    if request.method == 'GET':
        response_dict = []
        WordsWithSpecificLength = WordGame.query(ndb.AND(WordGame.word_length == word_length, WordGame.is_deleted == False))
        for word in WordsWithSpecificLength:
            TheWord = { hint : word.hint, word_length : word.word_length, game_id : word.game_id }
            response_dict.append(TheWord)
    else:
        abort(405)
        response_dict['error'] = 'Method not allowed'
    return json.dumps(response_dict)

@app.route('/games', methods=['POST'])
def create_game():
    game_property = {}
    logging.info(request.data)
    # convert from string to dictionary
    dataDictionary = json.loads(request.data)
    if request.method == 'POST':
        if 'word' not in dataDictionary or 'hint' not in dataDictionary or dataDictionary['word'] == '':
            game_property['error'] = 'Bad request, malformed data'
            abort(400)
        else:
            randomWord = WordGame.CreateWordGame(dataDictionary['word'], dataDictionary['hint'])
            randomWord.put()
            randomWord.game_id = str(randomWord.key.id())
            randomWord.put()
            game_property["hint"] = randomWord.hint
            game_property["word_length"] = randomWord.word_length
            game_property["game_id"] = str(randomWord.game_id)
    else:
        abort(405)
        game_property['error'] = 'Method not allowed'
    return json.dumps(game_property)

@app.route('/games/check_letter/<game_id>', methods=['POST'])
def game_check_letter(game_id):
    response_dict = {}
    response_dict['game_state'] = "ONGOING"
    response_dict['word_state'] = "____"
    response_dict['bad_guesses'] = 3;
    logging.debug(request.data)
    return json.dumps(response_dict)

@app.route('/token', methods=['GET', 'POST'])
def token():
    logging.info(request.data)
    logging.info(request.headers)
    logging.info("content-type" + str(request.content_type))
    auth = request.authorization
    UserDatabase = User.query()
    response_dict = {}
    # we query for any data from the database
    #TODO: encrypt the password!
    filteredPlayerData = UserDatabase.filter(User.Username == auth.username)
    playerData = filteredPlayerData.get()
    if request.method == 'GET':
        # checks whether there is such as player in the database and password is the same
        if playerData is None or playerData.Password != auth.password:
            logging.info("Username or Password is wrong!")
            #abort(404)
            response_dict['error'] = 'User not found'
        else:
            # this is the sign in method! So it will need to query from the ndb!
            session['user'] = auth.username
            session['score'] = playerData.games_won
            session['usertype'] = playerData.UserType
            logging.info("Player Token ID: {}".format(playerData.key.id()))
            response_dict['token'] = playerData.key.id()
    #Ensure that there is no player data!
    elif request.method == 'POST':
        # this is the sign up method! Store the user name and password at the server
        if playerData is not None:
            #throw an error!
            abort(409)
            response_dict['error'] = 'Conflicitng user id'
        else:
            # then begin to sign up the user!
            playerData = User(Username = auth.username, Password = auth.password, UserType = 'User', games_created = 0, games_lost = 0, games_played = 0, games_won = 0)
            # then u put the data into the datastore!
            playerData.put()
            session['user'] = auth.username
            session['score'] = 0
            session['usertype'] = playerData.UserType
            logging.info("Player Token ID: {}".format(playerData.key.id()))
            response_dict['token'] = playerData.key.id()
            # generate the token, store it
    else:
        response_dict['error'] = 'Method not allowed'
        abort(405)
    # return the token to the client
    return json.dumps(response_dict)

@app.route('/admin')
def admin_page():
    if 'user' not in session or session['usertype'] != 'Admin':
        response_dict = {}
        response_dict['error'] = 'You do not have permission to perform this operation'
        abort(403)
        return json.dumps(response_dict)
    return render_template('admin.html')

@app.route('/admin/players')
def admin_players():
    logging.info(request.args)
    response_list = []
    
    for i in range(10):
        response_dict = {}
        response_dict["name"] = "Name %d" % i
        response_dict["games_created"] = 10 + i * 2
        response_dict["games_played"] = i * 12
        response_dict["games_won"] = i
        response_dict["games_lost"] = 10 - i
        response_list.append(response_dict)
    return json.dumps(response_list)

@app.route('/admin/words')
def admin_words():
    logging.debug(request.args)
    response_list = []
    
    for i in range(10):
        response_dict = {}
        response_dict["word"] = "Word %d" % i
        response_dict["wins"] = 10 + i * 2
        response_dict["losses"] = i * 12
        response_list.append(response_dict)
    return json.dumps(response_list)

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.clear()
    return redirect(url_for('main'))

#@app.route('/new_game', methods=['POST'])
#def new_game():
#    """ Return a random word """
#    # words from http://randomword.setgetgo.com/get.php
#    word_to_guess = urllib2.urlopen('http://randomword.setgetgo.com/get.php').read()
#    
#    session['word_to_guess'] = word_to_guess.upper()
#    session['word_state'] = ["_"] * len(word_to_guess)
#    session['bad_guesses'] = 0#
#    # if there was no record of scores, we set it to 0
#    if 'games_won' not in session:
#        session['games_won'] = 0
#    if 'games_lost' not in session:
#        session['games_lost'] = 0
#    logging.debug("word to guess = %s" % word_to_guess)
#    #return escape(session)
#    return json.dumps({'word_length' : len(word_to_guess)})

@app.route('/check_letter', methods=['POST'])
def check_letter():
    if 'word_to_guess' not in session:
        reset_score()
        return redirect(url_for('main'))
    content = request.get_json()
    letter = content.get('guess', None).upper()
    logging.debug("Guessed letter %s" % letter)
    bad_guess = True
    game_state = "ONGOING"

    # set the state of the game
    word_to_guess = session['word_to_guess']
    for idx, char in enumerate(word_to_guess):
        if char == letter:
            session['word_state'][idx] = letter
            bad_guess = False
    
    #check if player is still in game, lose, or win game
    if bad_guess:
        session['bad_guesses'] += 1
        if session['bad_guesses'] > 7:
            game_state = "LOSE"
            session['games_lost'] += 1 
    else:
        #loop through the word state, if there is an _ character, game is still in progress
        for c in session['word_state']:
            if c == '_':
                break
        else: # no _ character found, game won!
            game_state = "WIN"
            session['games_won'] += 1

    logging.debug(str(session))

    # define the response based on the game state
    response_dict = {}
    response_dict['game_state'] = game_state
    response_dict['word_state'] = "".join(session['word_state'])
    if game_state == "ONGOING":
        response_dict['bad_guesses'] = session['bad_guesses']
    if game_state == "LOSE":
        response_dict['answer'] = session['word_to_guess'] 

    return json.dumps(response_dict)

@app.route("/score", methods=['GET', 'DELETE'])
def get_score():
    if request.method == 'DELETE':
        session['games_won'] = 0
        session['games_lost'] = 0
    
    return json.dumps({'games_won': session.get('games_won', 0), 'games_lost': session.get('games_lost', 0) })

@app.errorhandler(400)
def page_bad_request(e):
    logging.info('unexpected error: {}'.format(e), 400)
    return redirect('https://http.cat/400')

@app.errorhandler(403)
def page_not_forbidden(e):
    logging.info('unexpected error: {}'.format(e), 403)
    return redirect('https://http.cat/403')

@app.errorhandler(404)
def page_not_found(e):
    logging.info('unexpected error: {}'.format(e), 404)
    return redirect('https://http.cat/404')

@app.errorhandler(405)
def page_method_not_allowed(e):
    logging.info('unexpected error: {}'.format(e), 405)
    return redirect('https://http.cat/405')

@app.errorhandler(409)
def page_user_conflict(e):
    logging.info('unexpected error: {}'.format(e), 409)
    return redirect('https://http.cat/409')

@app.errorhandler(500)
def application_error(e):
    """Return a custom 500 error."""
    logging.info('unexpected error: {}'.format(e), 500)
    return redirect('https://http.cat/500')