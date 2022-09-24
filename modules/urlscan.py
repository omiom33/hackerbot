import requests
from virustotal_api import api

def Urlscan1(message):
	if api == "XXX":
		print(
			f"\033[93m *****************************************************\033[00m"
		)

		print(
			f"\033[93m Please fill in the virustotal_api.py for access virustotal api\033[00m"
		)

		print(
			f"\033[93m *****************************************************\033[00m"
		)


	else:
		try:

			headers = {
			  "Accept-Encoding": "gzip, deflate",
			  "User-Agent" : "gzip,  My Python requests library example client or username"
			  }
			params = {'apikey': api, 'resource': message} # message is target url
			response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
			  params=params, headers=headers)
			json_response = response.json()

			positives = json_response.get("positives") #detection
			total = json_response.get("total") # total scan
			scan = json_response.get("scans") # scan data


			print(
				f"\033[93m *****************************************************\033[00m"
			)


			for firms in scan: #List what they detected
				a = scan.get(firms)
				detected = str(a.get("detected"))
				if detected == "True":
					print(f"\033[92m {str(firms)}\033[00m : " + str(a.get("result")))



			print(f"\033[91m Detection ratio: {str(positives)}/{str(total)}\033[00m")

			print(
				f"\033[93m *****************************************************\033[00m"
			)


		except:
			print("Somethings wrong...")

