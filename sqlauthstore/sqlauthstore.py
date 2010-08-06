from trac.config import Option, ExtensionOption
from trac.core import *
from trac.perm import IPermissionGroupProvider

from acct_mgr.api import IPasswordStore
from acct_mgr.pwhash import IPasswordHashMethod

class SQLAuthStore(Component):
	"""
	This class implements SQL password store for Trac's AccountManager.
	"""

	hash_method = ExtensionOption('account-manager', 'hash_method', IPasswordHashMethod, 'HtPasswdHashMethod')

	auth_table = Option('account-manager', 'sql_auth_table', None,
		"""Name of the SQL table with authentication data. Trac should have access to it.""")

	implements(IPasswordStore)

	# IPasswordStore methods

	def get_users(self):
		"""
		Returns an iterable of the known usernames.
		"""

		if not self.auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return

		db = self.env.get_db_cnx()
		cursor = db.cursor()
		
		cursor.execute("SELECT DISTINCT username FROM %s ORDER BY username" % self.auth_table)

		for username, in cursor:
			yield username

	def has_user(self, user):
		"""
		Returns whether the user account exists.
		"""

		if not self.auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return False

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT username FROM %s WHERE username=%%s" % self.auth_table, (user,))

		for row in cursor:
			return True
		return False

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

		if not self.auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return None

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT password FROM %s WHERE username=%%s" % self.auth_table, (user,))

		for hash, in cursor:
			return self.hash_method.check_hash(user, password, hash)
		return None

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

		if not self.auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return []

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		cursor.execute("SELECT admin FROM %s WHERE username=%%s" % self.auth_table, (username,))

		for admin, in cursor:
			if int(admin):
				return ['admins', 'users']
			else:
				return ['users']
		return []
