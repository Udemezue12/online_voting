
import requests


def fetch_country_choices():
    url = "https://country-api-1.onrender.com/country/countries"
    response = requests.get(url)
    if response.status_code == 200:
        return [(country, country) for country in response.json()]
    else:
        return []


def fetch_states():
    url = "https://country-api-1.onrender.com/states/states"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {} 

states = fetch_states()  
countries = fetch_country_choices()