import SafeCreativeAPI

if __name__=='__main__':
	share_key=""
	priv_key =""
	api = SafeCreativeAPI.SafeCreativeAPI(share_key, priv_key, True)
	#Para que no se muestre el texto extra del modo debug
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
	if authorized == "false" or (level != "ADD" and level != "MANAGE"):
		authorized = api.getAuthorization_Url("ADD")
		print "Acceda ha",authorized,"para autorizar"
		exit()

	noncekey = SafeCreativeAPI.first_content(state, 'noncekey')
	data2register = {'title':'Test API python register',
					'text':'Test API python register works'}
	reg = api.work_register(noncekey, data2register)

	code = SafeCreativeAPI.first_content(reg, 'code')
	print "Se ha registrado con el codigo", code
