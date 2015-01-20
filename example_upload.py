#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SafeCreativeAPI

if __name__=='__main__':
	share_key=""
	priv_key =""

	api = SafeCreativeAPI.SafeCreativeAPI(share_key, priv_key, True)
	#Para que NO se muestre el texto extra del modo debug
	SafeCreativeAPI.DEBUG_MODE = False

	#Debemos insertar un usuario directamente o crear uno como es el caso
	api.AUTH_KEY = None
	api.AUTH_PRIVATE_KEY = None
	if api.AUTH_KEY is None or api.AUTH_PRIVATE_KEY is None:
		create = api.getAuthkey_create()
		print "Se han creado los pares, public key(", api.AUTH_KEY,") private key(", api.AUTH_PRIVATE_KEY,")"
	state = api.getAuthkey_state()

	authorized = SafeCreativeAPI.first_content(state, 'authorized')
	level = SafeCreativeAPI.first_content(state, 'level')
	noncekey = SafeCreativeAPI.first_content(state, 'noncekey')
	if authorized == "false":
		authorized = api.getAuthorization_Url("GET")
		print "Acceda ha",authorized,"para autorizar"
		exit()

	import sys, os
	if len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
		upload_id = api.upload_file(sys.argv[1])
		reg = api.work_register(noncekey, {'uploadticket':upload_id})
		code = SafeCreativeAPI.first_content(reg, 'code')

		print 'El fichero "%s" se ha registrado con el codigo: %s'%(os.path.basename(sys.argv[1]), code)
		
	else:
		print 'Inserte como para metro el fichero a registrar'
