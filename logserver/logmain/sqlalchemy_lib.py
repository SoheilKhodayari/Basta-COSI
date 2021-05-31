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
    Schema for the single SQLAlchemy attack vector database.
"""

import sys
import os
from sqlalchemy import create_engine
from sqlalchemy import Column, Date, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship, joinedload, subqueryload, Session

Base = declarative_base()
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AttackVectorModel(Base):

    __tablename__ = "cosi_attack_vectors"

    id = Column(Integer, primary_key=True)
    States = Column(String)
    LeakMethod = Column(String)	
    AttackClassType = Column(String)
    Inclusion = Column(String)	
    Browser = Column(String)	
    BrowserVersion = Column(String)

def get_or_create_sqlalchemy_session(siteId, db_name="attack_vectors.db"):
	"""
		gets or creates the connection session
	"""
	db_path_name = os.path.join(ROOT_DIR, os.path.join("automator", os.path.join(str(siteId), db_name)))
	connection_str = 'sqlite:///%s'%db_path_name
	logActionsToConsole = False
	engine = create_engine(connection_str, echo=logActionsToConsole)

	if not os.path.exists(db_path_name):
		Base.metadata.create_all(engine)	

	Session = sessionmaker(bind=engine)
	session = Session()    

	return session