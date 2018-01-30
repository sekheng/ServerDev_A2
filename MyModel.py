from google.appengine.ext import ndb
import string

class User(ndb.Model):
    Username = ndb.StringProperty()
    Password = ndb.TextProperty()
    UserType = ndb.StringProperty()
    games_created = ndb.IntegerProperty()
    games_lost = ndb.IntegerProperty()
    games_played = ndb.IntegerProperty()
    games_won = ndb.IntegerProperty()

    @staticmethod
    def CreateUser(_username, _password):
        return User(Username = _username, Password = _password, UserType = "User", games_created = 0, games_lost = 0, games_played = 0, games_won = 0)

class WordGame(ndb.Model):
    is_deleted = ndb.BooleanProperty()
    word = ndb.StringProperty()
    hint = ndb.StringProperty()
    word_length = ndb.IntegerProperty()
    game_id = ndb.StringProperty()
    number_of_tries = ndb.IntegerProperty()
    word_state = ndb.StringProperty()
    numbers_of_losses = ndb.IntegerProperty()
    numbers_of_wins = ndb.IntegerProperty()

    @staticmethod
    def CreateWordGame(_word, _hint):
        MyWord = WordGame(is_deleted = False, word = _word.upper(), hint = _hint, word_length = len(_word))
        MyWord.number_of_tries = 0
        MyWord.word_state = ""
        MyWord.numbers_of_losses = 0
        MyWord.numbers_of_wins = 0
        for num in range(0, len(_word)):
            MyWord.word_state += '_'
        return MyWord

    def ResetWordGame(self):
        if (self.word_state == self.word):
            self.numbers_of_wins += 1
        else:
            self.numbers_of_losses += 1
        self.word_state = ''
        for num in range(0, len(self.word)):
            self.word_state += '_'
        self.number_of_tries = 0
        self.put()