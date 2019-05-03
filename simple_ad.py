from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import logging
import os

logger = logging.getLogger(__name__)


class ActiveDirectory:
    """
    Impliments Active Directory lookups
    """
    def __init__(self, server=None, user=None, password=None):
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
        else:
            logger.error('AD whoami returned None. Check username / password are valid')
            exit(-1)

    def get_members(self, group_name, search_base):
        """
        Fetches a list of users that belong to a group

        :param group_name: Group name to search for
        :param search_base: Distinguished Name path to start search from
        :return: list
        """

        # Default member_list
        member_list = {'groupname': group_name, 'isADGroup': False, 'members': ''}
        logger.debug('get_members group_name: {}'.format(group_name))

        g = self.conn.search(
            search_base=search_base,
            search_filter='(&(objectClass=group)(cn={}))'.format(group_name),
            search_scope=SUBTREE,
            paged_size=5,
            attributes=['member'], size_limit=0
        )

        if g:
            if self.conn.entries.__len__() > 0:
                dn = self.conn.entries[0].entry_dn
                members = self.conn.entries[0].member.values
                member_list = {'groupname': group_name, 'isADGroup': True, 'members': members}

        return member_list

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

    def get_ad_group_drilldown(self, group_list, search_base):
        """
        Collects group member report attributes for multiple groups simultaneously.

        :param group_list: list of groups to look search
        :param search_base: distinguished name of search base
        :return: list of dicts
        """

        report_list = []
        for group in group_list:
            logger.debug('Group: {}'.format(group))
            user_report = []
            logger.debug(type(user_report))
            group_members = self.get_members(group, search_base)
            if group_members['members'].__len__() > 0:
                for member in group_members['members']:
                    logger.debug('Member: {}'.format(member))
                    r = self.get_user_report_attributes(user_search_base=member)
                    logger.debug('Report: {}'.format(r))
                    user_report.append(r)

            report_list.append({'group': group, 'isADGroup': group_members['isADGroup'], 'member_detail': user_report})

        return report_list

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
