from trac.config import Option, BoolOption, ExtensionOption
from trac.core import *
from trac.perm import IPermissionGroupProvider
from trac.web.api import ITemplateStreamFilter

from genshi.filters.transform import Transformer

from acct_mgr.api import IPasswordStore
from acct_mgr.pwhash import IPasswordHashMethod

class SQLAuthStore(Component):
	"""
	This class implements SQL password store for Trac's AccountManager.
	"""

	hash_method = ExtensionOption('account-manager', 'hash_method', IPasswordHashMethod, 'HtPasswdHashMethod')

	sql_auth_table = Option('account-manager', 'sql_auth_table', None,
		"""Name of the SQL table with authentication data. Trac should have access to it.""")
	sql_read_only = BoolOption('account-manager', 'sql_read_only', True,
		"""Is SQL table with authentication data read-only?""")

	implements(IPasswordStore, IPermissionGroupProvider, ITemplateStreamFilter)

	# IPasswordStore methods

	def get_users(self):
		"""
		Returns an iterable of the known usernames.
		"""

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return

		db = self.env.get_db_cnx()
		cursor = db.cursor()
	
		self.log.debug("sqlauthstore: get_users: SELECT DISTINCT username FROM %s ORDER BY username" % (self.sql_auth_table,))
		cursor.execute("SELECT DISTINCT username FROM %s ORDER BY username" % self.sql_auth_table)

		for username, in cursor:
			yield username

	def has_user(self, user):
		"""
		Returns whether the user account exists.
		"""

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return False

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		self.log.debug("sqlauthstore: has_user: SELECT username FROM %s WHERE username='%s'" % (self.sql_auth_table, user))
		cursor.execute("SELECT username FROM %s WHERE username=%%s" % self.sql_auth_table, (user,))

		for row in cursor:
			return True
		return False

	def set_password(self, user, password):
		"""
		Sets the password for the user. This should create the user account
		if it doesn't already exist.

		Returns True if a new account was created, False if an existing account
		was updated.
		"""

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return False

		hash = self.hash_method.generate_hash(user, password)
		db = self.env.get_db_cnx()
		cursor = db.cursor()

		self.log.debug("sqlauthstore: set_password: UPDATE %s SET password='%s' WHERE username='%s'" % (self.sql_auth_table, hash, user))
		cursor.execute("UPDATE %s SET password=%%s WHERE username=%%s" % self.sql_auth_table, (hash, user))

		if cursor.rowcount > 0:
			db.commit()
			return False
		
		self.log.debug("sqlauthstore: set_password: INSERT INTO %s (username, password) VALUES ('%s', '%s')" % (self.sql_auth_table, user, hash))
		cursor.execute("INSERT INTO %s (username, password) VALUES (%%s, %%s)" % self.sql_auth_table, (user, hash))

		db.commit()
		return True

	def __getattribute__(self, name):
		if name == 'set_password' and self.sql_read_only:
			raise AttributeError
		return super(SQLAuthStore, self).__getattribute__(name)

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

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return None

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		self.log.debug("sqlauthstore: check_password: SELECT password FROM %s WHERE username='%s'" % (self.sql_auth_table, user))
		cursor.execute("SELECT password FROM %s WHERE username=%%s" % self.sql_auth_table, (user,))

		for hash, in cursor:
			self.log.debug("sqlauthstore: check_password: retrieved hash from the database")
			return self.hash_method.check_hash(user, password, hash)
		return None

	def delete_user(self, user):
		"""
		Deletes the user account.

		Returns True if the account existed and was deleted, False otherwise.
		"""

		if self.sql_read_only:
			return False

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return False

		if not self.has_user(user):
			return False

		db = self.env.get_db_cnx()
		cursor = db.cursor()

		self.log.debug("sqlauthstore: delete_user: DELETE FROM %s WHERE username='%s'" % (self.sql_auth_table, user))
		cursor.execute("DELETE FROM %s WHERE username=%%s" % self.sql_auth_table, (user,))

		db.commit()
		return True

	# IPermissionGroupProvider methods

	def get_permission_groups(self, username):
		"""
		Returns a list of names of the groups that the user with the specified
		name is a member of.
		"""

		if not self.sql_auth_table:
			self.log.debug("sqlauthstore: 'sql_auth_table' configuration option is required")
			return []

		db = self.env.get_db_cnx()
		cursor = db.cursor()
		
		self.log.debug("sqlauthstore: get_permission_groups: SELECT admin FROM %s WHERE username='%s'" % (self.sql_auth_table, username))
		cursor.execute("SELECT admin FROM %s WHERE username=%%s" % self.sql_auth_table, (username,))

		for admin, in cursor:
			self.log.debug("sqlauthstore: sql_auth_table: retrieved admin flag from the database")
			if int(admin):
				return ['admins', 'users']
			else:
				return ['users']
		return []

	# ITemplateStreamFilter methods

	def filter_stream(self, req, method, filename, stream, data):
		"""
		Returns changed stream for `admin_users.html` template to change how
		account deletion is described if SQL table is read-only.

		`req` is the current request object, `method` is the Genshi render
		method (xml, xhtml or text), `filename` is the filename of the template
		to be rendered, `stream` is the event stream and `data` is the data for
		the current template.
		"""
		
		if self.sql_read_only and filename == 'admin_users.html':
			stream |= Transformer(".//input[@name='remove']").attr('value', 'Remove session and permissions data for selected accounts')
		return stream
