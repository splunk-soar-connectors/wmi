from __future__ import absolute_import, division, print_function, unicode_literals

from future import standard_library

from .wmi_wrapper import WmiClientWrapper

standard_library.install_aliases()

_ = WmiClientWrapper
