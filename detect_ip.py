#!/usr/bin/env python
#encoding:UTF-8
#version1.0

import os
import time
import ipaddress
from itertools import chain
from time import sleep
import pandas as pd
import urllib.request
from bs4 import BeautifulSoup
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def expand_shadow_element(element):
    shadow_root = browser.execute_script('return arguments[0].shadowRoot', element)
    return shadow_root

url = "https://www.virustotal.com/gui/ip-address/"
df = pd.read_csv(r"C:\Users\1601866252_47450.csv")
df_new = df[df['RemoteAddressIP4'].notnull()]
mydata = list(df_new.iloc[:, 23])

f = open(r"C:\Users\ip.txt", "w", encoding="utf-8")
for ip in mydata:
    t = ip.split()
    #s = t.split("[")[1].split("]")[0]
    f.write(str(t))
    f.write("\n")
    for i in range(0, len(t),1):
        chromedriver = "C:\Program Files (x86)\Google\Chrome\Application\chromedriver.exe"
        os.environ["webdriver.chrome.driver"] = chromedriver
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        browser = webdriver.Chrome(chromedriver, chrome_options=chrome_options)
        test_ip = url + t[i]
        browser.get(test_ip)
        time.sleep(10)
        root1 = browser.find_elements_by_tag_name('ip-address-view')
        for root1_kid in root1:
            shadow_root1 = expand_shadow_element(root1_kid)
            message = shadow_root1.find_element_by_tag_name('vt-ui-main-generic-report')
            text = message.get_attribute('detections-string')
            if text != "No interesting sightings for this IP address":
                print(t[i])
                browser.close()
                browser.quit()
                l = open("C:\\Users\\remoteip_" + time.strftime('%Y_%m_%d') + ".txt", "a", encoding="utf-8")
                l.write(t[i] + "：trouble\n")
                l.close()
                time.sleep(5)
            else:
                print("YA~")
                browser.close()
                browser.quit()
                l = open("C:\\Users\\remoteip_" + time.strftime('%Y_%m_%d') + ".txt", "a", encoding="utf-8")
                l.write(t[i] + "：No problem\n")
                l.close()
                time.sleep(5)
f.close
browser.close()
browser.quit()
