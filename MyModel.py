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

class RandomWord(ndb.Model):
    IsDeleted = ndb.BooleanProperty()
    Word = ndb.StringProperty()
    Hint = ndb.StringProperty()