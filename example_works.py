#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SafeCreativeAPI

if __name__=='__main__':
	share_key=""
	priv_key =""

	api = SafeCreativeAPI.SafeCreativeAPI(share_key, priv_key, True)
	#Para que NO se muestre el texto extra del modo debug
	SafeCreativeAPI.DEBUG_MODE = False

	#Podriamos insertar un usuario directamente o crear uno como es el caso
	api.AUTH_KEY = None
	api.AUTH_PRIVATE_KEY = None
	if api.AUTH_KEY is None or api.AUTH_PRIVATE_KEY is None:
		create = api.getAuthkey_create()
		print "Se han creado los pares, public key(", api.AUTH_KEY,") private key(", api.AUTH_PRIVATE_KEY,")"
	state = api.getAuthkey_state()

	authorized = SafeCreativeAPI.first_content(state, 'authorized')
	level = SafeCreativeAPI.first_content(state, 'level')
	if authorized == "false":
		authorized = api.getAuthorization_Url("GET")
		print "Acceda ha",authorized,"para autorizar"
		exit()

	lista_trabajos = api.getWork_list()
	recordtotal = int(SafeCreativeAPI.first_content(lista_trabajos, 'recordtotal'))
	pagetotal = int(SafeCreativeAPI.first_content(lista_trabajos, 'pagetotal'))

	print "Usted tiene",recordtotal,"registros en",pagetotal,"paginas"

	lista = SafeCreativeAPI.first_tag(lista_trabajos, 'list')
	for work in lista['tags']:
		if work['name'] == 'work':
			code = SafeCreativeAPI.first_content(work, 'code')
			title = SafeCreativeAPI.first_content(work, 'title')
			state = SafeCreativeAPI.first_content(work, 'state')
			print code+" "+title+" "+state
