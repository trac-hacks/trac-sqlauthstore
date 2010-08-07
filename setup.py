from setuptools import setup

VERSION = '0.1'
PACKAGE = 'sqlauthstore'

setup(
	name = 'SQLAuthStorePlugin',
	version = VERSION,
	description = "SQL password store for Trac's AccountManager.",
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
