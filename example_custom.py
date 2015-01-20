#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SafeCreativeAPI

if __name__=='__main__':
	share_key=""
	priv_key =""
	api = SafeCreativeAPI.SafeCreativeAPI(share_key, priv_key, True)
	#Para que NO se muestre el texto extra del modo debug
	SafeCreativeAPI.DEBUG_MODE = False
	api.getAuthkey_create()

	params = {"component": "authkey.state",\
			"ztime":api.getZtime(),\
			"sharedkey":share_key,\
			"authkey":api.AUTH_KEY}
	#Para que se muestre el texto extra del modo debug
	SafeCreativeAPI.DEBUG_MODE = True
	sig_info = api.readInfo(params,api.AUTH_PRIVATE_KEY,None,True)
	print "Responde:", sig_info, "\n"
	sig_info = SafeCreativeAPI.first_tag(sig_info, "tokens")
	if sig_info:
		print "Tokens contiene", len(sig_info["tags"]), "etiquetas"
