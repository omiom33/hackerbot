import requests
from virustotal_api import api


def Filescan1(message, banner="*" * 53, request_url="https://www.virustotal.com/vtapi/v2/file"):
	
	if api == "XXX":	
		print(f"\033[93m {banner}\033[00m")
		print("\033[93m Please fill in the virustotal_api.py for access to the API..\033[00m")
		print(f"\033[93m {banner}\033[00m")

	else:
		try:
			params = {'apikey': api}
			files = {'file': ('files', open(message, 'rb'))} # file name
			response = requests.post(f"{request_url}/scan", files=files, params=params)
			json_response = response.json()
			resource = json_response.get("resource") # resource 
			print(resource)

			params = {'apikey': api, 'resource': resource}
			headers = {
			  "Accept-Encoding": "gzip, deflate",
			  "User-Agent" : "gzip,  My Python requests library example client or username"
			  }
			response = requests.get(
				f"{request_url}/report", params=params, headers=headers
			)

			file_response = response.json()

			positives = file_response.get("positives") # detection number 
			total = file_response.get("total") # total scan
			scan = file_response.get("scans") # scan data
			print(f"\033[93m {banner}\033[00m")
			for firms in scan: #List what they detected
				a = scan.get(firms)
				detected = str(a.get("detected"))
				if detected == "True": 
					print(f'\033[92m {str(firms)}:{str(a.get("result"))}\033[00m')

			print(f"\033[91m Detection ratio: {str(positives)}/{str(total)}\033[00m")
			print(f"\033[93m {banner}\033[00m")

		except Exception:
			print("Something went wrong... Please check your file path...")
