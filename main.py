"""`main` is the top level module for your Flask application."""

# Import the Flask Framework
from flask import Flask, render_template, url_for, Response, redirect, make_response, request, jsonify, abort
# import requests failed miserably!
import logging
import urllib2
import random
import requests
import os
import string

app = Flask(__name__)
# Note: We don't need to call run() since our application is embedded within
# the App Engine WSGI application server.

# set the secret key.  keep this really secret:
app.secret_key = os.urandom(24)
#logger = logging.getLogger()
#logging.getLogger().setLevel(logging.DEBUG)




@app.route('/')
def main():
    """Return a friendly HTTP greeting."""
    # assign a new id to the player if 
    if 'user' in session:
        logging.debug('Logged in as %s' % escape(session['user']))
    else:
        session['user'] = "".join(random.choice(string.lowercase) for x in xrange(5))
        session['score'] = 0
        logging.debug("New user, %s" % (str(session)))

    game_list = []
    for i in range(10):
        game = {}
        game['word_length'] = i
        game['hint'] = 'Game hint %d' % i
        game['game_id'] = 'gameid%d' % i
        game_list.append(game)
    return render_template('main.html', game_list=game_list, signed_in = True, sign_in_name = 'Tokki')

@app.route('/games/<game_id>', methods=['GET', 'DELETE'])
def games(game_id):
    game_property = {}
    game_property["hint"] = "I'm a word"
    game_property["word_length"] = 7
    game_property["game_id"] = game_id

    logging.debug("In game %s" % game_id)

    if request.method == 'DELETE':
        response_dict = {}
        response_dict['message'] = "Game was deleted"
        logging.debug(request.data);
        return json.dumps(response_dict)

    return render_template('game.html', game_property = game_property)

@app.route('/games/check_letter/<game_id>', methods=['POST'])
def game_check_letter(game_id):
    response_dict = {}
    response_dict['game_state'] = "ONGOING"
    response_dict['word_state'] = "____"
    response_dict['bad_guesses'] = 3;
    logging.debug(request.data);

    return json.dumps(response_dict)

@app.route('/games', methods=['POST'])
def create_game():
    logging.debug(request.data)
    logging.debug(request.get_json())
    game_property = {}
    game_property["hint"] = "I'm a word"
    game_property["word_length"] = 7
    game_property["game_id"] = "rrf"
    return json.dumps(game_property)

@app.route('/token', methods=['GET', 'POST'])
def token():
    logging.debug(request.data)
    logging.debug(request.headers)
    logging.debug("content-type" + str(request.content_type))
    # generate the token, store it
    # return the token to the client
    response_dict = {}
    response_dict['token'] = 'This is my generated token'
    return json.dumps(response_dict)

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/admin/players')
def admin_players():
    logging.debug(request.args)
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

@app.route('/new_game', methods=['POST'])
def new_game():
    """ Return a random word """
    # words from http://randomword.setgetgo.com/get.php
    word_to_guess = urllib2.urlopen('http://randomword.setgetgo.com/get.php').read()
    
    session['word_to_guess'] = word_to_guess.upper()
    session['word_state'] = ["_"] * len(word_to_guess)
    session['bad_guesses'] = 0

    # if there was no record of scores, we set it to 0
    if 'games_won' not in session:
        session['games_won'] = 0
    if 'games_lost' not in session:
        session['games_lost'] = 0
    logging.debug("word to guess = %s" % word_to_guess)
    #return escape(session)
    return json.dumps({'word_length' : len(word_to_guess)})

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
    

@app.errorhandler(404)
def page_not_found(e):
    """Return a custom 404 error."""
    return 'Sorry, Nothing at this URL.', 404


@app.errorhandler(500)
def application_error(e):
    """Return a custom 500 error."""
    return 'Sorry, unexpected error: {}'.format(e), 500
