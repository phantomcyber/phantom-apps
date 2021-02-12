from jamf_connector import JamfConnector

jamf = JamfConnector()
jamf.config = {
    #'base_url': 'https://tryitout.jamfcloud.com/JSSResource',
    'base_url': 'https://splunkdev.jamfcloud.com/JSSResource',
    #'base_url': 'https://splunkdev.jamfcloud.com/JSSResource',
    'username': 'phantom',
    'password': 'password',
    'verify_server_cert': False
    }

jamf.initialize()

#jamf.action_identifier = 'get_users':
jamf.action_identifier = 'get_system_info'
#jamf.handle_action({'username': 'AHarrison'})
jamf.handle_action({'id': '40'})
