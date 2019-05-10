#!/usr/bin/env python

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import logging
import os
import traceback
import argparse
import getpass


class ActiveDirectory:
    """
    Impliments Active Directory lookups
    """
    def __init__(self, server=None, user=None, password=None, search_base=None, loglevel=None):
        """
        Init method, binds to Active Directory and tests for connection.

        :param server: AD domain controller hostname or IP
        :param user: AD user with read access to the directory in the form of DOMAIN\\USER
        :param password: AD user password
        """
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO, format='%(message)s')

        if loglevel == 'DEBUG':
            logging.getLogger().setLevel(logging.DEBUG)

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
        self.logger.debug('Connecting to Active Directory server {}.'.format(self.server))
        self.conn.bind()
        self.logger.debug('Binding to Active Directory.')
        if self.conn.extend.standard.who_am_i():
            self.logger.info('AD connection established, user: {}'.format(self.conn.extend.standard.who_am_i()))
            return True
        else:
            self.logger.error('AD whoami returned None. Check username / password are valid')
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

        self.logger.debug(search_base)
        try:
            u = self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                paged_size=5,
                size_limit=0
            )

            entries = None
            if u:
                if self.conn.entries.__len__() > 0:
                    self.logger.debug('Found {} matching record in directory'.format(self.conn.entries.__len__()))
                    entries = self.conn.entries[0]

            return entries

        except Exception as e:
            self.logger.error('ERROR: {} \n {}'.format(e, traceback.print_tb(e.__traceback__)))

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
        else:
            self.logger.error('LDAP group {} not found.'.format(group_name))
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
            self.logger.warning('Could not find attribute {} for {}'.format(attribute,object['cn']))
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


def run():
    scriptargs = configure()
    if scriptargs:
        if scriptargs.environ:
            a = ActiveDirectory()
        else:
            passwd = getpass.getpass('Active Directory Bind account password: ')
            if scriptargs.server is None:
                print("Server is a required parameter.")
                exit(-1)
            if scriptargs.username is None:
                print("Username is a required parameter")
                exit(-1)
            if scriptargs.search_base is None:
                print("Guessing the search base based on the server name.")
                a = ActiveDirectory(server=scriptargs.server, user=scriptargs.username, password=passwd)
            else:
                a = ActiveDirectory(server=scriptargs.server, user=scriptargs.username,
                                    search_base=scriptargs.search_base, password=passwd)

    search_type = input('Search User or Group [u|g]: ')

    if search_type.lower() == 'user' or search_type.lower() == 'u':
        print('1. Search by samAccountName')
        print('2. Search by cn')
        print('3. Search by dn')
        search_number = input('Search by number: ')
        search_string = input('Search string: ')

        data = None
        if int(search_number) == 1:
            data = a.get_user_by_samaccountname('{}'.format(search_string))
        if int(search_number) == 2:
            data = a.get_user_by_cn('{}'.format(search_string))
        if int(search_number) == 3:
            data=a.get_user_by_dn('{}'.format(search_string))

    if search_type.lower() == 'group' or search_type.lower() == 'g':
        group_name = input('Group Name: ')
        data = a.get_group('{}'.format(group_name))
        if not data:
            exit(-1)

    filter_attr = input("Filter Attribute (enter for ALL): ")
    if filter_attr:
        if filter_attr in data:
            for i in sorted(data[filter_attr]):
                print(i)
        else:
            print("Attribute {} does not exist in the object".format(filter_attr))
    else:
        print(data)

def configure():
    parser = argparse.ArgumentParser('Simple wrapper for python-ldap3 for common AD searches.')
    parser.add_argument('--server',help='Active Directory Domain Controller to connect to.')
    parser.add_argument('--username', help='Active Directory Bind User. Format of "domain\\username".')
    parser.add_argument('--search_base', help='LDAP search path to limit queries to.')
    parser.add_argument('--environ', help='User Environment Variables to set script parameters. Overrides all others.',
                        action='store_true')

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    run()
