from __future__ import absolute_import, division, print_function, unicode_literals

from AccessControl.Permissions import add_user_folders
from Products import PluggableAuthService as PAS
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from .plugin import Plugin

import os


ZMI_DIR = os.path.join(os.path.dirname(__file__), 'zmi')


def manage_addLDAPAlchemyPlugin(dispatcher, id_, title='', RESPONSE=None, **kw):
    """Create instance of Plugin.
    """
    plugin = Plugin(id_, title, **kw)
    dispatcher._setObject(plugin.getId(), plugin)
    if RESPONSE is not None:
        RESPONSE.redirect('manage_workspace')


manage_addLDAPAlchemyPluginForm = PageTemplateFile(
    os.path.join(ZMI_DIR, 'add_plugin.pt'),
    globals(),
    __name__='addLDAPAlchemyPlugin'
)


def initialize(context):
    # XXX: do we need both? some plugins get away with either one
    # Should we test whether plugin is already in MultiPlugins? see sqlalchemy
    PAS.registerMultiPlugin(plugin.Plugin.meta_type)
    context.registerClass(
        plugin.Plugin,
        permission=add_user_folders,
        icon=os.path.join(ZMI_DIR, 'ldapalchemy.png'),
        constructors=(manage_addLDAPAlchemyPluginForm,
                      manage_addLDAPAlchemyPlugin),
        visibility=None
    )
