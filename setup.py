from setuptools import setup

VERSION = '0.0'
PACKAGE = 'mysqlauthstore'

setup(
	name = 'MySQLAuthStorePlugin',
	version = VERSION,
	description = "MySQL password store for Trac's AccountManager",
	author = 'Mitar',
	author_email = 'mitar@tnode.com',
	url = 'http://mitar.tnode.com/',
	keywords = 'trac plugin',
	license = "GPL",
	packages = [PACKAGE],
	include_package_data = True,
	install_requires = [
		'TracAccountManager',
	],
	zip_safe = False,
	entry_points = {
		'trac.plugins': '%s = %s' % (PACKAGE, PACKAGE),
	},
)
