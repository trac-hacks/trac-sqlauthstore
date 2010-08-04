from trac.core import *
from trac.perm import IPermissionGroupProvider

from acct_mgr.api import IPasswordStore

USERS_TABLE = 'test.users'

class MySQLAuthStore(Component):
	"""
	This class implements MySQL password store for Trac's AccountManager.
	"""

	def __init__(self, *args, **kwargs):
		# TODO: Do plugin configuration
		super(MySQLAuthStore, self).__init__(*args, **kwargs)

	implements(IPasswordStore)

	# IPasswordStore methods

	def get_users(self):
		"""
		Returns an iterable of the known usernames.
		"""

		db = self.env.get_db_cnx()
		cursor = db.cursor()
		
		cursor.execute("SELECT DISTINCT username FROM %s ORDER BY username" % USERS_TABLE)

		for username in cursor:
			yield username

	def has_user(self, user):
		"""
		Returns whether the user account exists.
		"""

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT username FROM %s WHERE username=%%s" % USERS_TABLE, (user,))
		username = cursor.fetchone()

		return True if username else False

	# Setting password or creating users not supported.
	#def set_password(self, user, password):

	def check_password(self, user, password):
		"""
		Checks if the password is valid for the user.
	
		Returns True if the correct user and password are specfied. Returns
		False if the incorrect password was specified. Returns None if the
		user doesn't exist in this password store.

		Note: Returing `False` is an active rejection of the login attempt.
		Return None to let the auth fall through to the next store in the
		chain.
		"""

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT password=PASSWORD(%%s) FROM %s WHERE username=%%s" % USERS_TABLE, (password, user))
		match = cursor.fetchone()

		if not match:
			return None
		else:
			return True if int(match[0]) else False

	def delete_user(self, user):
		"""
		Deletes the user account.

		Returns True if the account existed and was deleted, False otherwise.
		"""

		raise TracError("Deleting users not supported.")

	# IPermissionGroupProvider methods

	def get_permission_groups(self, username):
		"""
		Returns a list of names of the groups that the user with the specified
		name is a member of.
		"""

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT admin FROM %s WHERE username=%%s" % USERS_TABLE, (username,))
		admin = cursor.fetchone()

		if not admin:
			return []
		elif int(admin[0]):
			return ['admins', 'users']
		else:
			return ['users']

