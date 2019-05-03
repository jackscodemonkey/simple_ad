from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import logging
import os

logger = logging.getLogger(__name__)


class ActiveDirectory:
    """
    Impliments Active Directory lookups
    """
    def __init__(self, server=None, user=None, password=None, search_base=None):
        """
        Init method, binds to Active Directory and tests for connection.

        :param server: AD domain controller hostname or IP
        :param user: AD user with read access to the directory in the form of DOMAIN\\USER
        :param password: AD user password
        """
        if server is None:
            if 'AD_SERVER' in os.environ:
                server = os.environ.get('AD_SERVER')

        if user is None:
            if 'AD_USER' in os.environ:
                user = os.environ.get('AD_USER')

        if password is None:
            if 'AD_PASSWORD' in os.environ:
                password = os.environ.get('AD_PASSWORD')

        if search_base is None:
            if 'AD_SEARCH_BASE' in os.environ:
                self.search_base = os.environ.get('AD_SEARCH_BASE')
            else:
                self.search_base = self.guess_root_dn(server)

        self.server = Server(server, get_info=ALL, use_ssl=True)
        self.conn = Connection(self.server,
                               user=user,
                               password=password,
                               auto_bind=False,
                               authentication=NTLM,
                               return_empty_attributes=True)

        # Bind the connection
        bind = self._bind_ad()

    def _bind_ad(self):
        self.conn.open()
        logger.debug('Connecting to Active Directory server {}.'.format(self.server))
        self.conn.bind()
        logger.debug('Binding to Active Directory.')
        if self.conn.extend.standard.who_am_i():
            logger.info('AD connection established, user: {}'.format(self.conn.extend.standard.who_am_i()))
            return True
        else:
            logger.error('AD whoami returned None. Check username / password are valid')
            exit(-1)

    def guess_root_dn(self, ad_server):
        x = ad_server.split('.')
        x.pop(0)
        y = ""
        for i in x:
            y = y + ',DC={}'.format(i)

        z = y.lstrip(',')
        return z

    def _do_search(self, search_filter, dn=None):

        if dn:
            search_base = dn
        else:
            search_base = self.search_base

        try:
            u = self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )

            if u:
                if self.conn.entries.__len__() > 0:
                    logger.debug('Found {} matching record in directory'.format(self.conn.entries.__len__()))
                    entries = self.conn.entries[0]

            return entries

        except Exception as e:
            logger.error(e)

    def get_user_by_samaccountname(self, username):
            search_filter = '(&(objectClass=Person)(sAMAccountName={}))'.format(username)
            u = self._do_search(search_filter=search_filter)
            return u

    def get_user_by_cn(self, cn):
        search_filter = '(&(objectClass=Person)(cn={}))'.format(cn)
        u = self._do_search(search_filter=search_filter)
        return u

    def get_user_by_dn(self, dn):
        search_filter = '(&(objectClass=Person)'
        search_base = dn
        u = self._do_search(search_filter=search_filter, search_base=search_base)
        return u

    def get_group(self, group_name):
        """
        Fetches a list of users that belong to a group

        :param group_name: Group name to search for
        :return: list
        """
        group = None

        search_filter = '(&(objectClass=group)(cn={}))'.format(group_name),
        g = self._do_search(search_filter=search_filter)

        if g:
            if self.conn.entries.__len__() > 0:
                group = self.conn.entries[0]

        return group

    def isaduser(self, search_base, **kwargs):
        """
        Checks Active Directory to see if the requested user is a member of the domain.

        Search can be based on a proper Distinguished name passed as the search base with no other parameters,
        or search_base is your root of the search and user_name is the sAMAccount you're looking for.

        :param search_base: Distinguished Name path to a user or the root DN to start a search from
        :param kwargs: optional, pass user_name to search for sAMAccountName with a DN search base.
        :return: dict
        """
        user_name = kwargs.get('user_name', None)

        # Default user_list
        user_dict = {'isADUser': False, 'user_name': user_name}

        if user_name:
            u = self.conn.search(
                search_base=search_base,
                search_filter='(&(objectClass=Person)(sAMAccountName={}))'.format(user_name),
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )
        else:
            u = self.conn.search(
                search_base=search_base,
                search_filter='(&(objectClass=Person))',
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )

        if u:
            if self.conn.entries.__len__() > 0:
                user_dict = {'isADUser': True, 'user_name': user_name}

        return user_dict

    def get_user_attributes(self, search_base, **kwargs):
        """
        Grabs all attributes from an AD User object.

        Search can be based on a proper Distinguished name passed as the search base with no other parameters,
        or search_base is your root of the search and user_name is the sAMAccount you're looking for.

        :param search_base: Distinguished Name path to a user or the root DN to start a search from
        :param kwargs: optional, pass user_name to search for sAMAccountName with a DN search base.
        :return: dict
        """

        user_name = kwargs.get('user_name', None)

        # Default user_list
        user_dict = {'isADUser': False, 'attributes': ''}

        if user_name:
            u = self.conn.search(
                search_base = search_base,
                search_filter='(&(objectClass=Person)(sAMAccountName={}))'.format(user_name),
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )
        else:
            u = self.conn.search(
                search_base=search_base,
                search_filter='(&(objectClass=Person))',
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )

        if u:
            if self.conn.entries.__len__() > 0:
                user_dict = {'isADUser': True, 'attributes': self.conn.entries[0]}

        return user_dict

    def get_user_report_attributes(self, search_base, **kwargs):
        """
        Filters specific user attributes used in the EAS Security Audit report.

        sAMAccountName
        first_name
        last_name
        title
        mail
        distinguishedName
        company
        department

        :param search_base: Distinguished Name path to a user or the root DN to start a search from
        :param kwargs: optional, pass user_name to search for sAMAccountName with a DN search base.
        :return: dict
        """
        user_name = kwargs.get('user_name', None)

        if user_name is None:
            user = self.get_user_attributes(search_base=search_base)
        else:
            user = self.get_user_attributes(search_base=search_base, user_name=user_name)

        mgr = {}
        if user['isADUser']:
            if self.validate_attribute(user['attributes'], 'manager'):
                manager_dn = self.get_user_attributes(user['attributes']['manager'].value)
                if manager_dn:
                    manager_attributes = self.get_user_report_attributes(user['attributes']['manager'].value)
                    mgr = manager_attributes
            else:
                logger.warning('Unable to retrieve manager attribute for {}.'.format(user['attributes']['sAMAccountName'].value))

            _sAMAccountName = ''
            _first_name = ''
            _last_name = ''
            _title = ''
            _mail = ''
            _distinguishedName = ''
            _company = ''
            _department = ''

            if self.validate_attribute(user['attributes'], 'sAMAccountName'):
                _sAMAccountName = user['attributes']['sAMAccountName'].value
            if self.validate_attribute(user['attributes'], 'givenName'):
                _first_name = user['attributes']['givenName'].value
            if self.validate_attribute(user['attributes'], 'sn'):
                _last_name = user['attributes']['sn'].value
            if self.validate_attribute(user['attributes'], 'title'):
                _title = user['attributes']['title'].value
            if self.validate_attribute(user['attributes'], 'mail'):
                _mail = str(user['attributes']['mail'].value).lower()
            if self.validate_attribute(user['attributes'], 'distinguishedName'):
                _distinguishedName = str(user['attributes']['distinguishedName'].value)
            if self.validate_attribute(user['attributes'], 'company'):
                _company = str(user['attributes']['company'].value)
            if self.validate_attribute(user['attributes'], 'department'):
                _department = str(user['attributes']['department'].value)
            if self.validate_attribute(user['attributes'], 'userAccountControl'):
                _userAccountControl = str(user['attributes']['userAccountControl'].value)

            user_object = {
                    'sAMAccountName': _sAMAccountName,
                    'first_name': _first_name,
                    'last_name': _last_name,
                    'title': _title,
                    'mail': _mail,
                    'distinguishedName': _distinguishedName,
                    'company': _company,
                    'department': _department,
                    'manager': [mgr],
                    'userAccountControl': self.calculate_useraccountcontrol(int(_userAccountControl)),
                }

        return user_object

    def validate_attribute(self, object, attribute):
        """
        Validates that a value exists for an AD object's attribute.

        :param object: AD object
        :param attribute: Attribute to validate
        :return: bool
        """
        try:
            value = object[attribute]
            if value:
                return True
            else:
                return False
        except Exception as ex:
            logger.warning('Could not find attribute {} for {}'.format(attribute,object['cn']))
            return False

    def calculate_useraccountcontrol(self,account_int):
        """
        Calculates if user object is Enabled or Disabled in Active Directory based on its
        useraccountcontrol attribute value.

        :param account_int: int representing the useraccountcontrol
        :return: string
        """
        _values={
            '512': 'Enabled',
            '514': 'Disabled',
            '66048': 'Enabled Do not Expire',
            '66050': 'Disabled Do not Expire',
        }
        for k, v in _values.items():
            if int(k) == account_int:
                return v
        return account_int
