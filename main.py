"""`main` is the top level module for your Flask application."""

# Import the Flask Framework
from flask import Flask, render_template, url_for, Response, redirect, make_response, request, jsonify, abort, session, escape, app
from google.appengine.ext import ndb
from googleapiclient import discovery
from oauth2client import client
from werkzeug.security import generate_password_hash, check_password_hash
# import requests failed miserably!
import logging
import urllib2
import random
import requests
import httplib2
import os
import string
import json
import re
from MyModel import *
from datetime import *

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

def TimeOut_User(func):
    def function_wrapper():
        # 1st we  to check whether the time is up! and player even existed!
        if 'MyDateTime' in session and check_player_exists():
            # compare the data time!
            pass
        return func
    return function_wrapper

@TimeOut_User
@app.route('/')
def main():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds = 9999999)
    """Return a friendly HTTP greeting."""
    # assign a new id to the player if 
    signed_inFlag = False
    sign_in_Username = ''
    if check_player_exists() == True:
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
            respondWord = {'hint' : randomword.hint, 'word_length' : randomword.word_length, 'game_id' : randomword.game_id }
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
    wordDatabase = WordGame.query(ndb.AND(WordGame.game_id == game_id, WordGame.is_deleted == False))
    specificWord = wordDatabase.get()
    if specificWord is None:
        logging.info('game is not found')
        game_property['error'] = 'Game not found'
        abort(404)
    else:
        if 'user' not in session:
            abort(403)
            game_property['error'] = 'You do not have permission to perform this operation'
        elif request.method == 'GET':
            logging.info('beginning the game')
            game_property['hint'] = specificWord.hint
            game_property['word_length'] = specificWord.word_length
            game_property['game_id'] = specificWord.game_id
            playerDatabase = User.query(User.Username == session['user'])
            thePlayer = playerDatabase.get()
            thePlayer.games_played += 1
            thePlayer.put()
            return render_template('game.html', game_property = game_property)
        elif request.method == 'DELETE':
            logging.info('deleteing the specific game')
            playerDatabase = User.query(User.Username == session['user'])
            thePlayer = playerDatabase.get()
            if specificWord.owner_id != thePlayer.Username:
                simper_permission_error()
            else:
                specificWord.is_deleted = True
                specificWord.put()
                game_property['message'] = 'Game was deleted'
                return render_template('main.html', game_property = game_property)
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
            TheWord = { 'hint' : word.hint, 'word_length' : word.word_length, 'game_id' : word.game_id }
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
        elif check_player_exists() == False:
            game_property['error'] = 'You do not have permission to perform this operation'
            abort(403)
        else:
            # record it inside the player's data
            playerDatabase = User.query(User.Username == session['user'])
            thePlayer = playerDatabase.get()
            thePlayer.games_created += 1
            thePlayer.put()
            randomWord = WordGame.CreateWordGame(dataDictionary['word'], dataDictionary['hint'], thePlayer.Username)
            randomWord.put()
            randomWord.game_id = 'A' + str(randomWord.key.id())
            randomWord.put()
            game_property["hint"] = randomWord.hint
            game_property["word_length"] = randomWord.word_length
            game_property["game_id"] = str(randomWord.game_id)
    else:
        abort(405)
        game_property['error'] = 'Method not allowed'
    return json.dumps(game_property)

@app.route('/games/check_letter/<string:game_id>', methods=['POST'])
def game_check_letter(game_id):
    response_dict = {}
    # get specific game with the id!
    wordGameDB = WordGame.query(ndb.AND(WordGame.game_id == game_id, WordGame.is_deleted == False))
    specificWord = wordGameDB.get()
    logging.info('specificWord with id: ' + specificWord.game_id)
    if specificWord is None:
        response_dict['error'] = 'Game not found'
        abort(404)
    else:
        if request.method == 'POST':
            # Get the data dictionary
            dataDictionary = json.loads(request.data)
            if 'guess' not in dataDictionary or dataDictionary['guess'] is None or (not isinstance(dataDictionary['guess'], basestring)) or len(dataDictionary['guess']) > 1 or not dataDictionary['guess'].isalpha():
                if dataDictionary['guess'] == '':
                    # empty string means send back the same data!
                    response_dict['word_state'] = specificWord.word_state
                    response_dict['game_state'] = 'ONGOING'
                    response_dict['bad_guesses'] = specificWord.number_of_tries
                else:
                    logging.info('Trying to hack through check letter game id!')
                    response_dict = simper_malform_data_error()
            elif check_player_exists() == False:
                response_dict['error'] = 'You do not have permission to perform this operation'
                abort(403)
            else:
                guessedLetter = dataDictionary['guess']
                # check for regulary expression after meking a thorough check that there is onlyn a single letter
                reResult = re.match('[A-Za-z]', guessedLetter)
                if reResult is None:
                    logging.info('regex test failed')
                    response_dict['error'] = 'Bad request, malformed data'
                    abort(400)
                else:
                    checkWhetherGuessCorrectly = False
                    logging.info('checking for correct letter')
                    # get the list of the specific word
                    listOfWordState = list(specificWord.word_state)
                    for num in range(0, len(specificWord.word)):
                        if guessedLetter == specificWord.word[num]:
                            checkWhetherGuessCorrectly = True
                            listOfWordState[num] = guessedLetter
                    specificWord.word_state = "".join(listOfWordState)
                    specificWord.put()
                    logging.info("Current word state: " + specificWord.word_state)
                    logging.info("Guessed word: " + specificWord.word)
                    response_dict['game_state'] = 'ONGOING'
                    response_dict['word_state'] = specificWord.word_state
                    if checkWhetherGuessCorrectly == False:
                        specificWord.number_of_tries += 1
                        specificWord.put()
                        if specificWord.number_of_tries == 8:
                            response_dict['game_state'] = 'LOSE'
                            response_dict['answer'] = specificWord.word
                            # then add to the player's record
                            specificWord.ResetWordGame()
                            # get the player records!
                            playerDatabase = User.query(User.Username == session['user'])
                            thePlayer = playerDatabase.get()
                            thePlayer.games_lost += 1
                            thePlayer.put()
                            return json.dumps(response_dict)
                    else:
                        if specificWord.word == specificWord.word_state:
                            response_dict['game_state'] = 'WIN'
                            playerDatabase = User.query(User.Username == session['user'])
                            thePlayer = playerDatabase.get()
                            thePlayer.games_won += 1
                            thePlayer.put()
                            specificWord.ResetWordGame()
                            return json.dumps(response_dict)
                    response_dict['bad_guesses'] = specificWord.number_of_tries
        else:
            response_dict['error'] = 'Method not allowed'
            abort(405)
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
        if playerData is None or check_password_hash(playerData.Password, auth.password) == False:
            logging.info("Username or Password is wrong!")
            #abort(404)
            response_dict['error'] = 'User not found'
        else:
            # this is the sign in method! So it will need to query from the ndb!
            session['user'] = auth.username
            session['score'] = playerData.games_won
            session['usertype'] = playerData.UserType
            response_dict['token'] = str(playerData.key.id())
            session['token'] = response_dict['token']
            session['MyDateTime'] = datetime.now()
    #Ensure that there is no player data!
    elif request.method == 'POST':
        # this is the sign up method! Store the user name and password at the server
        if playerData is not None:
            #throw an error!
            abort(409)
            response_dict['error'] = 'Conflicting user id'
        else:
            # then begin to sign up the user!
            hashedPassword = generate_password_hash(auth.password)
            playerData = User(Username = auth.username, Password = hashedPassword, UserType = 'User', games_created = 0, games_lost = 0, games_played = 0, games_won = 0)
            # then u put the data into the datastore!
            playerData.put()
            session['user'] = auth.username
            session['score'] = 0
            session['usertype'] = playerData.UserType
            # generate the token, store it
            response_dict['token'] = str(playerData.key.id())
            session['token'] = response_dict['token']
    else:
        response_dict['error'] = 'Method not allowed'
        abort(405)
    # return the token to the client
    return json.dumps(response_dict)

@app.route('/oauth2callback', methods = ['GET'])
def oauth2callback():
    flow = client.flow_from_clientsecrets(
    'client_secret_1069847106666-t8n8vt90pr6148psjpjbqapc2bpj2rai.apps.googleusercontent.com.json',
    scope='https://www.googleapis.com/auth/plus.login',
    redirect_uri=url_for('oauth2callback', _external=True))
    
    if 'code' not in request.args:
        logging.info('code not in request.args')
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        session['credentials'] = credentials.to_json()
        credentialDict = json.loads(session['credentials'])
        # start recoding down the credential details
        session['usertype'] = 'User'
        #credentialsDict = credentials_to_dict(credentials)
        session['token'] = credentialDict['refresh_token']
        http_auth = credentials.authorize(httplib2.Http())
        plus_service = discovery.build('plus', 'v1', http_auth)
        playername = plus_service.people().get(userId='me').execute()
        playerGoogleName = playername['displayName']
        formatStrClientSecret = str(credentialDict['client_secret'])
        # we check for client id and secret!
        UserDatabase = User.query(User.Username == playerGoogleName)
        specificUser = UserDatabase.get()
        if specificUser is None:
            #it is new player! create it!
            specificUser = User.CreateUser(playerGoogleName, formatStrClientSecret)
            specificUser.put()
        session['user'] = specificUser.Username
        session['score'] = specificUser.games_won
        return redirect(url_for('main'))

@app.route('/auth')
def handle_auth_response():
    if 'error' in request.args:
        return simper_page_error()
    else:
        return None

#def credentials_to_dict(_credentials):
#    return {'token': _credentials.token,
#          'refresh_token': _credentials.refresh_token,
#          'token_uri': _credentials.token_uri,
#          'client_id': _credentials.client_id,
#          'client_secret': _credentials.client_secret,
#          'scopes': _credentials.scopes}

@app.route('/revoke', defaults={'what': ''})
@app.route('/revoke/<what>')
def revoke(what):
    auth_mechanism = []
    if not what or what == 'token':
        if 'credentials' in session:
            credentials = client.OAuth2Credentials.from_json(session['credentials'])
            credentials.revoke(httplib2.Http())
        auth_mechanism.append("token")
    if not what or what == 'session':
        if 'credentials' in session:        
            del session['credentials']
        auth_mechanism.append("session")
    if not auth_mechanism:
        auth_mechanism.append("All")

    return "%s Credentials Revoked" % " and ".join(auth_mechanism)

@app.route('/admin', methods = ['GET'])
def admin_page():
    response_dict = {}
    if check_player_exists() == False or session['usertype'] != 'Admin':
        response_dict = simper_permission_error()
        return json.dumps(response_dict)
    elif request.method != 'GET':
        response_dict['error'] = 'Method not allowed'
        abort(405)
    return render_template('admin.html')

@app.route('/admin/players', methods = ['GET'])
def admin_players():
    response_dict = {}
    if check_player_exists() == False or session['usertype'] != 'Admin':
        response_dict = simper_permission_error()
    elif request.method != 'GET':
        response_dict = simper_method_error()
    elif 'order' not in request.args or 'sortby' not in request.args:
        response_dict = simper_malform_data_error()
    else:
        response_dict = []
        # query for players only! then sort the user database
        UserDatabase = None
        if request.args['sortby'] == 'wins':
            if request.args['order'] == 'desc':
                UserDatabase = User.query().order(-User.games_won)
            else:
                UserDatabase = User.query().order(User.games_won)
        elif request.args['sortby'] == 'losses':
            if request.args['order'] == 'desc':
                UserDatabase = User.query().order(-User.games_lost)
            else:
                UserDatabase = User.query().order(User.games_lost)
        elif request.args['sortby'] == 'alphabetical':
            if request.args['order'] == 'desc':
                UserDatabase = User.query().order(-User.Username)
            else:
                UserDatabase = User.query().order(User.Username)
        else:
            response_dict = simper_malform_data_error()
        for userData in UserDatabase:
            userJson = { 'name' : userData.Username, 'games_created' : userData.games_created, 'games_played' : userData.games_played, 'games_won' : userData.games_won, 'games_lost' : userData.games_lost }
            response_dict.append(userJson)
    return json.dumps(response_dict)

@app.route('/admin/words', methods = ['GET'])
def admin_words():
    response_dict = None
    if check_player_exists() == False or session['usertype'] != 'Admin':
        response_dict = simper_permission_error()
    elif request.method != 'GET':
        response_dict = simper_method_error()
    elif 'sortby' not in request.args or 'order' not in request.args:
        response_dict = simper_malform_data_error()
    else:
        response_dict = []
        sortKeyword = request.args['sortby']
        orderKeyword = request.args['order']
        wordDatabase = None
        if sortKeyword == 'solved':
            if orderKeyword == 'desc':
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(-WordGame.numbers_of_wins)
            else:
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(WordGame.numbers_of_wins)
        elif sortKeyword == 'length':
            if orderKeyword == 'desc':
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(-WordGame.word_length)
            else:
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(WordGame.word_length)
        elif sortKeyword == 'alphabetical':
            if orderKeyword == 'desc':
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(-WordGame.word)
            else:
                wordDatabase = WordGame.query(WordGame.is_deleted == False).order(WordGame.word)
        else:
            response_dict = simper_malform_data_error()
        for theWord in wordDatabase:
            wordDict = { 'word' : theWord.word, 'wins' : theWord.numbers_of_wins, 'losses' : theWord.numbers_of_losses}
            response_dict.append(wordDict)
    return json.dumps(response_dict)

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.clear()
    return redirect(url_for('main'))

@app.route('/score',methods=['GET'])
def getScore():
    if check_player_exists() == False:
        return simper_permission_error()
    else:
        PlayerDB = User.query(User.Username == session['user'])
        specificPlayer = PlayerDB.get()
        return jsonify(games_won=specificPlayer.games_won, games_lost=specificPlayer.games_lost)

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


def check_player_exists():
    if 'user' in session and 'usertype' in session and 'token' in session:
        return True
    else:
        return False

def simper_malform_data_error():
    abort(400)
    response_dict = {}
    response_dict['error'] = 'Bad request, malformed data'
    return response_dict

def simper_method_error():
    abort(405)
    response_dict = {}
    response_dict['error'] = 'Method not allowed'
    return response_dict

def simper_permission_error():
    abort(403)
    response_dict = {}
    response_dict['error'] = 'You do not have permission to perform this operation'
    return response_dict

def simper_page_error():
    abort(404)
    response_dict = {}
    response_dict['error'] = 'Page not found'
    return response_dict