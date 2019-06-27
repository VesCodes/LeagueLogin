#!/usr/bin/env python2

import getpass
import league_login


if __name__ == "__main__":
    username = raw_input("username: ")
    password = getpass.getpass("password: ")

    region_data = league_login.get_region_data("euw1")

    lq = league_login.Queue(region_data)
    lq.login(username, password)

    print(lq.token)
