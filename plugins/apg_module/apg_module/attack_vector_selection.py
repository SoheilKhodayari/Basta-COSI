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
	Attack Vector Selection Algorithm.

	This script calculates a score for each side channel based on the number
	of states that it allow to distinguish as well as the number of browsers 
	the side channel works on.

	Usage:
	---------------
	> select_attack_vectors(siteId, target_state, browsers)

"""

import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sqlalchemy_path= os.path.join(ROOT_DIR, os.path.join("logserver", "logmain"))
sys.path.insert(0, sqlalchemy_path)

from sqlalchemy_lib import AttackVectorModel, get_or_create_sqlalchemy_session
from sqlalchemy.sql import select
import copy


# --------------------------------------------------------------------------------- #
#		Utility Functions
# --------------------------------------------------------------------------------- #

def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        d[column.name] = str(getattr(row, column.name))

    return d

def get_score_av(permutations, attack_vector):

	# return 0 if the attack vector can not cover any permutations
	coverable_perms = get_covered_permutations(permutations, attack_vector)
	n_coverable_perms = len(coverable_perms)

	# return 0 if the attack vector can not cover any NEW permutations that is required
	any_coverable_perm = False
	for p1 in coverable_perms:
		for p2 in permutations:
			if str(p1) == str(p2):
				any_coverable_perm = True
				break; 

	if n_coverable_perms == 0 or not any_coverable_perm:
		return 0

	CSP_WEIGHT = 1
	NORMAL_WEIGHT = 3
	CSP_ATTACK_TYPE = "CSP"
	attack_type = attack_vector["LeakMethod"]
	score = 0
	if attack_type == CSP_ATTACK_TYPE:
		score = CSP_WEIGHT * n_coverable_perms
	else:
		score = NORMAL_WEIGHT * n_coverable_perms
	return score

def get_best_av(permutations, attack_vectors):
	max_vector = attack_vectors[0]
	max_score = get_score_av(permutations, max_vector)

	for av in attack_vectors:
		sc = get_score_av(permutations, av)
		if  sc > max_score:
			max_vector = av
			max_score = sc

	return max_vector, max_score

def get_covered_permutations(permutations, attack_vector):
	attack_vector_covered_perms = []
	for each_state in attack_vector["States"][1]:
		perm = [each_state, [attack_vector["Browser"], attack_vector["BrowserVersion"]] ]
		attack_vector_covered_perms.append(perm)
	return attack_vector_covered_perms	

def remove_covered_permutations(permutations, attack_vector):
	attack_vector_covered_perms = get_covered_permutations(permutations, attack_vector)

	out_perms = permutations
	for p in attack_vector_covered_perms:
		for element in out_perms:
			if str(p) == str(element):
			#if p[0] == element[0] and p[1][0] == element[1][0] and p[1][1] == element[1][1]:
				out_perms.remove(element)

	return out_perms


# --------------------------------------------------------------------------------- #
#		Attack Vector Selection Algorithm 
# --------------------------------------------------------------------------------- #

def select_attack_vectors(siteId, target_state, target_browsers=[["firefox", "60.0"], ["chrome", "74.0.3729.131"], ["edge", "44.17763.1.0"]]):

	db = get_or_create_sqlalchemy_session(siteId)
	out_vectors = []

	# A
	all_attack_vectors = db.query(AttackVectorModel).all()

	all_state_pairs = db.query(AttackVectorModel.States).distinct().all()
	all_states = []
	for item in all_state_pairs:
		pair = item[0]
		pair = eval(pair)
		s1= pair[0]
		s2 = pair[1]
		if s1 not in all_states:
			all_states.append(s1)
		if s2 not in all_states:
			all_states.append(s2)
	# S_r
	all_states_except_target = copy.deepcopy(all_states)
	if target_state in all_states_except_target:
		all_states_except_target.remove(target_state)

	# P: permutation of state and browser to cover
	permutations = []
	for each_state in all_states_except_target:
		for each_browser in target_browsers:
			item = [each_state, each_browser]
			permutations.append(item)

	# Filter: A_r
	related_attack_vectors = []
	for av in all_attack_vectors:
		if target_state in av.States:
			related_attack_vectors.append(av)

	related_attack_vectors = [row2dict(row) for row in related_attack_vectors]

	# Merge: A_r
	merged_attack_vectors = []
	for i in range(len(related_attack_vectors)):
		av = related_attack_vectors[i]
		match_flag = False
		for j in range(len(related_attack_vectors)):
			if i == j: continue
			other_av = related_attack_vectors[j]
			if (av["LeakMethod"] == other_av["LeakMethod"]) and (av["Browser"] == other_av["Browser"]) \
				and (av["BrowserVersion"] == other_av["BrowserVersion"]) and \
				(eval(av["Inclusion"])['inclusion'] == eval(other_av["Inclusion"])['inclusion'] ):
					# same attack-class and SD-URL, thus merge
					match_flag = True
					av_pair = eval(str(av["States"]))
					other_av_pair = eval(str(other_av["States"]))
					index = 0
					if target_state in av_pair:
						index = av_pair.index(target_state)
						av_pair.remove(target_state)

					if target_state in other_av_pair:
						other_av_pair.remove(target_state)
					merged_states = []
					for st in av_pair:
						if st not in merged_states:
							merged_states.append(st)
					for st in other_av_pair:
						if st not in merged_states:
							merged_states.append(st)
					
					newAV = copy.deepcopy(av)
					 # differentiates the target state from other states
					newAV["States"] = [target_state, merged_states]
					# determine what is state_a and state_b
					newAV["TargetStateIndex"] = index 
					merged_attack_vectors.append(newAV)

		if not match_flag:
			av_pair = eval(str(av["States"]))
			if target_state in av_pair:
				index = av_pair.index(target_state)
				av_pair.remove(target_state)
				av["TargetStateIndex"] = index 
			av["States"] = [target_state, av_pair]
			merged_attack_vectors.append(av)

		for i in range(len(related_attack_vectors)):
			av = related_attack_vectors[i]
			for j in range(len(merged_attack_vectors)):
				merged_av = merged_attack_vectors[j]
				if (av["LeakMethod"] == merged_av["LeakMethod"]) and (av["Browser"] == merged_av["Browser"]) \
					and (av["BrowserVersion"] == merged_av["BrowserVersion"]) \
					and (eval(av["Inclusion"])['inclusion'] == eval(other_av["Inclusion"])['inclusion'] ):
					new_states = merged_av["States"][1]
					for s in av["States"][1]:
						if s not in new_states:
							new_states.append(s)	
					merged_av["States"][1] = new_states
					merged_attack_vectors[j] = merged_av

		for j in range(len(merged_attack_vectors)):
			item = merged_attack_vectors[j]
			if 'u' in item["States"][1]:
				item["States"][1].remove('u')
	# end Merge A_r

	score = 1
	while len(permutations) and len(merged_attack_vectors) and score > 0:
		av, score = get_best_av(permutations, merged_attack_vectors)
		if score > 0:
			permutations = remove_covered_permutations(permutations, av)
			out_vectors.append(av)
			merged_attack_vectors.remove(av)
	
	return out_vectors

# --------------------------------------------------------------------------------- #
#			Test 
# --------------------------------------------------------------------------------- #
def main():
	"""
	Example Usage
	"""
	
	siteId = 101
	target_state= 'Reviewer2-LoggedIn'
	browsers = [["firefox", "60.0"], ["chrome", "74.0.3729.131"], ["edge", "44.17763.1.0"]]
	candidate_attack_vectors = select_attack_vectors(siteId, target_state, browsers)
	print candidate_attack_vectors

if __name__ == "__main__":
	main()
