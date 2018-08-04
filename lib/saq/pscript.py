#!/usr/bin/env python3
#
# "profile script"
#
# [profile_point] {type = value} -> {type = value}
#
# example '[The malware communicates with a domain in an expected skmfeed TLD.] {analysis = "VxStream Analysis"} --> {url = "kboi" OR url = "bcvboi" OR url = "klinks" OR url = "bkbo.exe" OR url = "kk10" OR url = "kk-101" OR url = "k-k101" OR url = "stark"}'

# string constants for the language
CONST_BOOLEAN_AND = 'AND'
CONST_BOOLEAN_OR = 'OR'
CONST_BOOLEAN_NOT = 'NOT'
CONST_DEPTH_SHORT = '->'
CONST_DEPTH_LONG = '-->'
CONST_SUBSTRING_MATCH = '=~'
CONST_STRING_MATCH = '='
CONST_REGEX_MATCH = '~'

# valid target types
TYPE_ANALYSIS = 'analysis'

try:
    # all observables types are valid targets
    from saq.constants import VALID_OBSERVABLE_TYPES, VALID_TARGETS
except ImportError:
    # we may just want to check syntax
    # so then we don't need the whole saq library
    pass

# regex rules for tokens
def t_PROFILE_POINT(t):
    r'\[[^\]]+\]'
    t.value = t.value[1:-1] # remove the leading ending delimiters
    return t

t_NOT = r'NOT'
t_AND = r'AND'
t_OR = r'OR'

t_DEPTH_SHORT = r'-\>'
t_DEPTH_LONG = r'--\>'

t_LCURLY = r'{'
t_RCURLY = r'}'

t_LPAREN = r'\('
t_RPAREN = r'\)'

t_EQUALS = r'='
t_REGEX = r'~'
t_SUBSTRING = r'=~'

def t_COMMENT(t):
    r'\#.*'
    pass

def t_STRING(t):
    r'".*?(?<!\\)"'
    # escaped \" becomes "
    t.value = t.value.replace(r'\"', '"')
    t.value = t.value[1:-1] # remove the leading and ending quotes
    return t

reserved = {
    'AND': 'AND',
    'OR': 'OR',
    'NOT': 'NOT',
}

def t_NAME(t):
    r'[a-zA-Z0-9_][.a-zA-Z0-9_-]*'
    t.type = reserved.get(t.value, 'NAME')
    return t

def t_error(t):
    print("Illegal character {}".format(t.value[0]))
    t.lexer.skip(1)

def t_eof(t):
    return None

tokens = (
    'PROFILE_POINT',
    'NOT',
    'AND',
    'OR',
    'DEPTH_SHORT',
    'DEPTH_LONG',
    'LCURLY',
    'RCURLY',
    'LPAREN',
    'RPAREN',
    'EQUALS',
    'SUBSTRING',
    'REGEX',
    'STRING',
    'NAME',
)

# ignore whitespace
t_ignore = ' \t\r\n'

precedence = (
    ('right', 'NOT'),
    ('left', 'AND', 'OR'),
    ('left', 'DEPTH_SHORT', 'DEPTH_LONG'),
)

# abstract syntax tree

class _and(object):
    def __init__(self, e1, e2):
        self.e1 = e1
        self.e2 = e2

    def __call__(self, target):
        return self.e1(target) and self.e2(target)

    def __str__(self):
        return "{} AND {}".format(self.e1, self.e2)

class _or(object):
    def __init__(self, e1, e2):
        self.e1 = e1
        self.e2 = e2

    def __call__(self, target):
        return self.e1(target) or self.e2(target)

    def __str__(self):
        return "{} OR {}".format(self.e1, self.e2)

class _not(object):
    def __init__(self, e1):
        self.e1 = e1

    def __call__(self, target):
        return not self.e1(target)

    def __str__(self):
        return "NOT {}".format(self.e1)

# in order to resolve source we have to compare the expression "source" to every node
# that is a valid source target

class _search(object):
    def __init__(self, source, depth, search):
        self.source = source
        self.depth = depth
        self.search = search

        self.matched_target = None

    def __call__(self, root):
        import logging
        from saq.analysis import Analysis, Observable

        def _short_search(target):
            # if the depth is short then we just look at this object and any children objects
            # if this object has any targets then we look at those too as well as any targets of the children objects
            target_list = [ target ]
            if hasattr(target, 'targets'):
                target_list.extend(target.targets)
            if target.children:
                target_list.extend(target.children)
                for child in target.children:
                    if hasattr(child, 'targets'):
                        target_list.extend(child.targets)

            for target in target_list:
                if self.search(target):
                    self.matched_target = target
                    return True

            return False

        # otherwise it's a deep search so we use recursive scanning
        def _deep_search(target, visited=None):

            # remember what nodes we've visited
            # because nodes can refer to previous nodes in the tree
            if visited is None: visited = []
            visited.append(target)

            # does our expression match this target?
            if self.search(target):
                self.matched_target = target
                return True

            # or any profile point targets found inside this target? (these are not considered "children")
            if hasattr(target, 'targets'):
                for obj in target.targets:
                    if self.search(obj):
                        self.matched_target = obj
                        return True

            # otherwise we keep looking
            if isinstance(target, Analysis):
                for observable in target.observables:
                    if observable not in visited:
                        result = _deep_search(observable, visited)
                        if result:
                            return True
            elif isinstance(target, Observable):
                for analysis in target.all_analysis:
                    if analysis not in visited:
                        result = _deep_search(analysis, visited)
                        if result:
                            return True

            return False
            
        # compute what source objects to start looking from
        # NOTE we do NOT look at ProfilePointTargets as source points
        for obj in root.all: # look through the entire tree (all includes both analysis and observables)
            if self.source(obj):
                # this is an object we should look at
                if self.depth == CONST_DEPTH_SHORT:
                    if _short_search(obj):
                        return True
                elif self.depth == CONST_DEPTH_LONG:
                    if _deep_search(obj):
                        return True
                
        return False

    def __str__(self):
        return "{} {} {}".format(self.source, self.depth, self.search)

class _match(object):
    def __init__(self, type, match_type, value):
        import re

        self.type = type
        self.match_type = match_type
        self.value = value
        self.regex = None

        if match_type == CONST_REGEX_MATCH:
            self.regex = re.compile(self.value)

    def __call__(self, target):
        # these are the three target types we support
        from saq.analysis import Analysis, Observable, ProfilePointTarget

        if self.type == TYPE_ANALYSIS:
            if not isinstance(target, Analysis):
                #logging.warning("type was {} but instance type was {}".format(TYPE_ANALYSIS, type(target)))
                return False

            # if there is no Summary then we don't bother matching
            if target.summary is None:
                return False

            if self.match_type == CONST_STRING_MATCH:
                return target.summary == self.value
            if self.match_type == CONST_SUBSTRING_MATCH:
                return self.value in target.summary 
            elif self.match_type == CONST_REGEX_MATCH:
                m = self.regex.search(str(target.summary))
                if m:
                    return True

        elif self.type in VALID_OBSERVABLE_TYPES:
            if not isinstance(target, Observable):
                return False

            if self.match_type == CONST_STRING_MATCH:
                return target.value == self.value
            elif self.match_type == CONST_SUBSTRING_MATCH:
                return self.value in target.value
            elif self.match_type == CONST_REGEX_MATCH:
                m = self.regex.search(target.value)
                if m:
                    return True

        elif self.type in VALID_TARGETS:
            if not isinstance(target, ProfilePointTarget):
                return False

            if self.type != target.name:
                return False

            if self.match_type == CONST_STRING_MATCH:
                # XXX what if data is bytes?
                return self.value == target.data
            elif self.match_type == CONST_SUBSTRING_MATCH:
                return self.value in target.data
            elif self.match_type == CONST_REGEX_MATCH:
                m = self.regex.search(target.value)
                if m:
                    return True

        return False

    def __str__(self):
        return "{} {} {}".format(self.type, self.match_type, self.value)

class PScript(object):
    def __init__(self, description, expression):
        self.description = description
        self.expression = expression
        self.root = None

    def __call__(self, root):
        from saq.analysis import RootAnalysis
        assert isinstance(root, RootAnalysis)
        self.root = root
        return self.expression(root)

    def __str__(self):
        return str(self.expression)

# syntax parsing

def p_profile_point(t):
    """profile_point : PROFILE_POINT expression"""
    t[0] = PScript(t[1], t[2])

def p_expression(t):
    """expression : expression OR expression
                   | expression AND expression
                   | NOT expression
                   | LPAREN expression RPAREN 
                   | search_expression """

    if t[1] == CONST_BOOLEAN_NOT:
        t[0] = _not(t[2])
    elif len(t) == 2:
        t[0] = t[1]
    elif t[2] == CONST_BOOLEAN_OR:
        t[0] = _or(t[1], t[3])
    elif t[2] == CONST_BOOLEAN_AND:
        t[0] = _and(t[1], t[3])
    elif t[1] == '(' and t[3] == ')':
        t[0] = t[2]

def p_search_expression(t):
    """search_expression : search_target DEPTH_SHORT search_target
                         | search_target DEPTH_LONG search_target"""
    if t[2] == CONST_DEPTH_SHORT:
        t[0] = _search(t[1], t[2], t[3])
    elif t[2] == CONST_DEPTH_LONG:
        t[0] = _search(t[1], t[2], t[3])

def p_search_target(t):
    """search_target : LCURLY search_operation RCURLY"""
    t[0] = t[2]

def p_search_operation(t):
    """search_operation : search_operation OR search_operation
                        | search_operation AND search_operation
                        | NOT search_operation
                        | LPAREN search_operation RPAREN
                        | NAME EQUALS STRING
                        | NAME REGEX STRING
                        | NAME SUBSTRING STRING"""

    if t[1] == CONST_BOOLEAN_NOT:
        t[0] = _not(t[2])
    elif t[2] == CONST_BOOLEAN_OR:
        t[0] = _or(t[1], t[3])
    elif t[2] == CONST_BOOLEAN_AND:
        t[0] = _and(t[1], t[3])
    elif t[2] == CONST_STRING_MATCH:
        t[0] = _match(t[1], t[2], t[3])
    elif t[2] == CONST_REGEX_MATCH:
        t[0] = _match(t[1], t[2], t[3])
    elif t[2] == CONST_SUBSTRING_MATCH:
        t[0] = _match(t[1], t[2], t[3])

def p_error(t):
    if t is None:
        print("End of file reached before search was finished.")
        return

    print("Syntax error at {}".format(t))

def compile_pscript(source):

    import ply.lex as lex
    import ply.yacc as yacc

    lexer = lex.lex()
    parser = yacc.yacc()

    return parser.parse(source)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'r') as fp:
        for line in fp.readlines():
            print(compile_pscript(line))
