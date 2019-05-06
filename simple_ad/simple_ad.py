from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import logging
import os
import traceback

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

        logger.debug(search_base)
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
            logger.error('ERROR: {} \n {}'.format(e, traceback.print_tb(e.__traceback__)))

    def get_user_by_samaccountname(self, username):
            search_filter = '(&(objectClass=Person)(sAMAccountName={}))'.format(username)
            u = self._do_search(search_filter=search_filter)
            return u

    def get_user_by_cn(self, cn):
        search_filter = '(&(objectClass=Person)(cn={}))'.format(cn)
        u = self._do_search(search_filter=search_filter)
        return u

    def get_user_by_dn(self, dn):
        search_filter = '(&(objectClass=Person))'
        u = self._do_search(search_filter=search_filter, dn=dn)
        return u

    def get_group(self, group_name):
        """
        Fetches a list of users that belong to a group

        :param group_name: Group name to search for
        :return: list
        """
        group = None

        search_filter = '(&(objectClass=group)(cn={}))'.format(group_name)
        g = self._do_search(search_filter=search_filter)

        if g:
            if self.conn.entries.__len__() > 0:
                group = self.conn.entries[0]

        return group

    def get_group_members(self, group_name):
        members = []
        group_object = self.get_group(group_name=group_name)
        for m in group_object.member:
            members.append(m)

        return members

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
