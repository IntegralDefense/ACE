# vim: sw=4:ts=4:et

import mmap
import os.path
import re

from saq.constants import *

__all__ = [ 
    'get_email',
    'COMPRESSION_FILE_EXTENSIONS'
]

def get_email(root):
    """Returns the main EmailAnalysis object, or None if there isn't one."""
    from saq.modules.email import EmailAnalysis

    for analysis in root.all_analysis:
        if isinstance(analysis, EmailAnalysis) and analysis.email is not None:
            return analysis

    return None

# the list of all known file extensiosn for known compression types
# https://en.wikipedia.org/wiki/List_of_archive_formats (9/25/2017)
COMPRESSION_FILE_EXTENSIONS = [
    '.a', 
    '.ar',
    '.cpio',
    '.shar',
    '.LBR',
    '.iso',
    '.lbr',
    '.mar',
    '.sbx',
    '.tar',
    '.bz2',
    '.gz',
    '.lz',
    '.lzma',
    '.lzo',
    '.rz',
    '.sfark',
    '.sz',
    '.xz',
    '.z',
    '.Z',
    '.7z',
    '.s7z',
    '.ace',
    '.afa',
    '.alz',
    '.apk',
    '.arc',
    '.arj',
    '.b1',
    '.ba',
    '.bh',
    '.cab',
    '.car',
    '.cfs',
    '.cpt',
    '.dar',
    '.dd',
    '.dgc',
    '.dmg',
    '.ear',
    '.gca',
    '.ha',
    '.hki',
    '.ice',
    '.jar',
    '.kgb',
    '.lzh',
    '.lha',
    '.lzx',
    '.pak',
    '.partimg',
    '.pea',
    '.pim',
    '.pit',
    '.qda',
    '.rar',
    '.rk',
    '.sda',
    '.sea',
    '.sen',
    '.sfx',
    '.shk',
    '.sit',
    '.sitx',
    '.sqx',
    '.tar.gz', '.tgz', '.tar.Z', '.tar.bz2', '.tbz2', '.tar.lzma', '.tlz',
    '.uc', '.uc0', '.uc2', '.ucn', '.ur2', '.ue2',
    '.uca',
    '.uha',
    '.war',
    '.wim',
    '.xar',
    '.xp3',
    '.yz1',
    '.zip', '.zipx',
    '.zoo',
    '.zpaq',
    '.zz' ]
