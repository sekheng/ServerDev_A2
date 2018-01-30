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

class WordGame(ndb.Model):
    is_deleted = ndb.BooleanProperty()
    word = ndb.StringProperty()
    hint = ndb.StringProperty()
    word_length = ndb.IntegerProperty()
    game_id = ndb.StringProperty()
    number_of_tries = ndb.IntegerProperty()
    word_state = ndb.StringProperty()

    @staticmethod
    def CreateWordGame(_word, _hint):
        MyWord = WordGame(is_deleted = False, word = _word.upper(), hint = _hint, word_length = len(_word))
        MyWord.number_of_tries = 0
        MyWord.word_state = ""
        for num in range(0, len(_word)):
            MyWord.word_state += '_'
        return MyWord

    def ResetWordGame(self):
        self.word_state = ''
        for num in range(0, len(self.word)):
            self.word_state += '_'
        self.number_of_tries = 0
        self.put()