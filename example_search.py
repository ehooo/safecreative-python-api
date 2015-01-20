#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SafeCreativeAPI

def search_workType_by_fields(api, code):
	seach_perm = {'workType.code':code}
	page = 1;
	pagetotal = 1;
	ret = {'recordtotal':0,
		   'pagetotal':0,
		   'records':[]}
	while page <= pagetotal:
		result = api.search_by_fields(seach_perm, page);
		recordtotal = int(SafeCreativeAPI.first_content(result, 'recordtotal'))
		pagetotal = int(SafeCreativeAPI.first_content(result, 'pagetotal'))
		if page == 1:
			ret['recordtotal'] = recordtotal
			ret['pagetotal'] = pagetotal
	
			lista = SafeCreativeAPI.first_tag(result, 'list')
			for work in lista['tags']:
				if work['name'] == 'work':
					code = SafeCreativeAPI.first_content(work, 'code')
					title = SafeCreativeAPI.first_content(work, 'title')
					license = SafeCreativeAPI.first_tag(work, 'license')
					license_shotname = SafeCreativeAPI.first_content(license, 'shortname')
					res = code+" "+title+" "+license_shotname
					ret['records'].append(res)
			page += 1
	return ret

def search_query(api, query):
	page = 1;
	pagetotal = 1;
	ret = {'recordtotal':0,
		   'pagetotal':0,
		   'records':[]}
	while page <= pagetotal:
		result = api.search_by_query(query, page);
		recordtotal = int(SafeCreativeAPI.first_content(result, 'recordtotal'))
		pagetotal = int(SafeCreativeAPI.first_content(result, 'pagetotal'))
		if page == 1:
			ret['recordtotal'] = recordtotal
			ret['pagetotal'] = pagetotal
	
			lista = SafeCreativeAPI.first_tag(result, 'list')
			for work in lista['tags']:
				if work['name'] == 'work':
					code = SafeCreativeAPI.first_content(work, 'code')
					title = SafeCreativeAPI.first_content(work, 'title')
					license = SafeCreativeAPI.first_tag(work, 'license')
					license_shotname = SafeCreativeAPI.first_content(license, 'shortname')
					res = code+" "+title+" "+license_shotname
					ret['records'].append(res)
			page += 1
	return ret

if __name__=='__main__':
	#Se conecta en modo prueba, es decir, a la "arena"
	api = SafeCreativeAPI.SafeCreativeAPI("", "", True)
	#Para que no se muestre el texto extra del modo debug
	SafeCreativeAPI.DEBUG_MODE = False

	result = search_workType_by_fields(api, 'technical')
	print "Encontradas", result['pagetotal'],"paginas usando workType"
	print "Encontrados", result['recordtotal'],"registros usando workType"
	for text in result['records']:
		print text
	result = search_query(api, 'technical')
	print "--------------------------------"
	print "Encontradas", result['pagetotal'],"paginas usando query"
	print "Encontrados", result['recordtotal'],"registros usando query"
	for text in result['records']:
		print text
