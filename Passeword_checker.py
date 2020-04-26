import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # The api works with the hashe of the password
    res = requests.get(url)
    if res.status_code != 200:  # 200 means all good, 400 means problems
        raise RuntimeError(f'Error fetching : {res.status_code}, check the API and try again')
    return res  # return all pwned tail hashed password begining with the query_char


def read_res(response):
    print(response.text)


def get_password_leaks_count(hashes, hash_to_check):
    hashe = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashe:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # gives the password hashed
    fisrt5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(fisrt5_char)  # gives only the first 5 char to the api for secure reasons
    print('\n',fisrt5_char, tail)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} time(s). You should probably change your password !!\n")
        else:
            print(f"{password} was NOT found. Carry on !\n")
    return '\nall done !'


if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
