#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Copyright (C) 2019  Soheil Khodayari, IMDEA Software
    Copyright (C) 2010 Watts Lab, Inc.
  
    This code is reused from the repository: https://github.com/jpwatts/publicsuffix

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You may not use this file except in compliance with the License.


"""

import httplib2

EFFECTIVE_TLD_NAMES = 'http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1'


def _normalize(s):
    # Leading dots are optional; remove them.
    if s.startswith('.'):
        s = s[1:]
    # Rules end at the first white space.
    s = s.split()[0]
    # Domains are case-insensitive.
    s = s.lower()
    # Only deal with Unicode.
    s = s.decode('utf-8')
    return s


class Rule(object):
    """A rule describing a public domain suffix.
    >>> com = Rule('.com')
    >>> com
    Rule(u'com')
    >>> com.match('.com')
    True
    >>> jpn_com = Rule('jpn.com')
    >>> jpn_com
    Rule(u'jpn.com')
    >>> jpn_com.match('.com')
    False
    >>> com.match('example.com')
    True
    >>> com.match('.net')
    False
    >>> uk = Rule('*.uk')
    >>> uk
    Rule(u'*.uk')
    >>> uk.match('co.uk')
    True
    >>> uk.match('parliament.uk')
    True
    >>> uk.match('bbc.co.uk')
    True
    >>> uk.match('www.bbc.co.uk')
    True
    >>> parliament = Rule('!parliament.uk')
    >>> parliament
    Rule(u'!parliament.uk')
    >>> parliament.is_exception
    True
    >>> parliament.match('co.uk')
    False
    >>> parliament.match('parliament.uk')
    True
    >>> parliament.match('www.parliament.uk')
    True
    >>> parliament.match('python.org')
    False
    """
    def __init__(self, s):
        self.is_exception = s.startswith('!')
        if self.is_exception:
            s = s[1:]
        s = _normalize(s)
        self.labels = tuple(reversed(s.split('.')))
        self.s = s

    def __repr__(self):
        s = unicode(self)
        return '%s(%r)' % (type(self).__name__, s)

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __unicode__(self):
        return u'%s%s' % (self.is_exception and '!' or '', self.s)

    def __cmp__(self, other):
        # All else being equal, rules with more labels sort first.
        if not cmp(self.is_exception, other.is_exception):
            return -1 * cmp(len(self.labels), len(other.labels))
        if self.is_exception:
            return 0 if other.is_exception else -1
        return 1 if other.is_exception else 0

    def match(self, domain):
        domain = _normalize(domain)
        labels = tuple(reversed(domain.split('.')))
        len_labels = len(labels)

        # A rule can't match a domain with fewer labels than itself.
        if len(self.labels) > len_labels:
            return False

        for i in range(len_labels):
            try:
                r_label = self.labels[i]
            except IndexError:
                break
            if r_label != '*' and labels[i] != r_label:
                return False
        return True


class SuffixList(list):
    """A list of rules for finding top-level domains.
    >>> psl = public_suffix_list()
    >>> psl.domain('www.example.com')
    u'example.com'
    >>> psl.tld('www.example.com')
    u'com'
    >>> psl.domain('example.com')
    u'example.com'
    >>> psl.tld('example.com')
    u'com'
    >>> psl.domain('.com') is None
    True
    >>> psl.tld('.com')
    u'com'
    >>> psl.domain('www.bbc.co.uk')
    u'bbc.co.uk'
    >>> psl.tld('www.bbc.co.uk')
    u'co.uk'
    >>> psl.domain('bbc.co.uk')
    u'bbc.co.uk'
    >>> psl.tld('bbc.co.uk')
    u'co.uk'
    >>> psl.domain('co.uk') is None
    True
    >>> psl.tld('co.uk')
    u'co.uk'
    >>> psl.domain('www.parliament.uk')
    u'parliament.uk'
    >>> psl.tld('www.parliament.uk')
    u'uk'
    >>> psl.domain('parliament.uk')
    u'parliament.uk'
    >>> psl.tld('parliament.uk')
    u'uk'
    >>> psl.parents('www.sub.domain.example.com')
    [u'sub.domain.example.com', u'domain.example.com', u'example.com']
    >>> psl.parent('www.sub.domain.example.com')
    u'sub.domain.example.com'
    >>> psl.parents('www.sub.domain.bbc.co.uk')
    [u'sub.domain.bbc.co.uk', u'domain.bbc.co.uk', u'bbc.co.uk']
    >>> psl.parent('www.sub.domain.bbc.co.uk')
    u'sub.domain.bbc.co.uk'
    >>> psl.parents('www.sub.domain.parliament.uk')
    [u'sub.domain.parliament.uk', u'domain.parliament.uk', u'parliament.uk']
    >>> psl.parent('www.sub.domain.parliament.uk')
    u'sub.domain.parliament.uk'
    >>> psl.parent('www.example.com')
    u'example.com'
    >>> psl.parent('example.com') is None
    True
    """
    def __init__(self, seq=None):
        super(SuffixList, self).__init__()
        if seq is not None:
            self += seq

    def __add__(self, seq):
        seq = [Rule(s) for s in seq if s and not s.startswith('//')]
        return type(self)(super(SuffixList, self).__add__(seq))

    def __iadd__(self, seq):
        for s in seq:
            self.append(s)

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__, super(SuffixList, self).__repr__())

    def append(self, s):
        self.insert(len(self), s)

    def insert(self, i, s):
        if s and not s.startswith('//'):
            super(SuffixList, self).insert(i, Rule(s))

    def domain(self, host):
        """Return the registered domain name for a given host name."""
        host = _normalize(host)
        tld = self.tld(host)
        if host != tld:
            return u'%s.%s' % (host[:-len(tld)-1].rsplit('.', 1)[-1], tld)

    def iter_parents(self, host):
        """Iterate over a host's parents, stopping at the registered domain."""
        host = _normalize(host)
        domain = self.domain(host)
        if host != domain:
            parent = host.split('.', 1)[1]
            while parent != domain:
                yield parent
                parent = parent.split('.', 1)[1]
            yield domain

    def parent(self, host):
        """Return a host's parent."""
        for parent in self.iter_parents(host):
            return parent

    def parents(self, host):
        """Return a list of a host's parents, ordered by specificity."""
        return list(self.iter_parents(host))

    def tld(self, host):
        """Return the top-level domain for a given host name."""
        host = _normalize(host)
        matches = sorted(r for r in self if r.match(host))
        if matches:
            rule = matches[0]
            len_rule_labels = len(rule.labels)
            if rule.is_exception:
                maxsplit = len_rule_labels - 1
            elif len(host.split('.')) == len_rule_labels:
                return host
            else:
                maxsplit = len_rule_labels
            return u'.'.join(host.rsplit('.', maxsplit)[1:])
        return host.rsplit('.', 1)[-1]


def public_suffix_list(url=EFFECTIVE_TLD_NAMES, headers=None, http=None):
    if http is None:
        import httplib2
        http = httplib2.Http()
    _response, content = http.request(url, headers=headers)
    return SuffixList(content.splitlines())
