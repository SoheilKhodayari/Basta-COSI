# -*- coding: utf-8 -*-

"""
	Copyright (C) 2019  Soheil Khodayari, IMDEA Software
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
	
	Description:
	---------------
	Attack Page Generator Class

"""


import json
from ef_attack_page_generator_cls import EFAttackPageGenerator
from op_attack_page_generator_cls import OPAttackPageGenerator
from cw_attack_page_generator_cls import CWAttackPageGenerator
from csp_attack_page_generator_cls import CSPAttackPageGenerator

class AttackPageGenerator(object):
    """
        a pluggable HTML attack page generator class for COSI attacks
    """

    def __init__(self, uuid, **kwargs):
        """
        @param uuid: object unique identifier
        @param kwargs: a dictionary containing composed attack classes (e.g. EF, CSP, etc)
        """
        self._uuid = uuid 
        for key in kwargs:
            setattr(self, key, kwargs[key])

        self._EF = EFAttackPageGenerator(uuid)
        self._OP = OPAttackPageGenerator(uuid, self._EF)
        self._CW = CWAttackPageGenerator(uuid, self._EF)
        self._CSP = CSPAttackPageGenerator(uuid, self._EF)

    def __unicode__(self):
        return 'APG ID-%s'%str(self._uuid)

    def __str__(self):
        return 'APG ID-%s'%str(self._uuid)

    def __repr__(self):
        return 'APG ID-%s'%str(self._uuid)

    # ----------------------------------------------------------------------- #
    #                   Common Public Methods
    # ----------------------------------------------------------------------- #

    def getID(self):
        return self._uuid

    def getEFInstance(self):
        """
            event fire attack-page generator instance
        """
        return self._EF

    def getOPInstance(self):
        """
            object properties attack-page generator instance
        """
        return self._OP

    def getCWInstance(self):
        """
            content window attack-page generator instance
        """
        return self._CW

    def getCSPInstance(self):
        """
           content-security-policy attack-page generator instance
        """
        return self._CSP
