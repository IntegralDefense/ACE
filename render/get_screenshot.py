#!/usr/bin/env python3

import argparse
import os.path
import zipfile

from configparser import ConfigParser

from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait # available since 2.4.0
from selenium.webdriver.support import expected_conditions as EC # available since 2.26.0

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def main_chrome(args):

    config = ConfigParser()
    config.read(args.config_path)
   
    try:
        PROXY_HOST = config['proxy']['host']
    except:
        PROXY_HOST = None
    try:
        PROXY_PORT = config['proxy'].getint('port')
    except:
        PROXY_PORT = None
    try:
        PROXY_USER = config['proxy']['user']
    except:
        PROXY_USER = None
    try:
        PROXY_PASS = config['proxy']['password']
    except:
        PROXY_PASS = None
    
    manifest_json = """
        {
            "version": "1.0.0",
            "manifest_version": 2,
            "name": "Chrome Proxy",
            "permissions": [
                "proxy",
                "tabs",
                "unlimitedStorage",
                "storage",
                "<all_urls>",
                "webRequest",
                "webRequestBlocking"
            ],
            "background": {
                "scripts": ["background.js"]
            },
            "minimum_chrome_version":"22.0.0"
        }
        """

    background_js = """
var config = {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "http",
            host: "%(host)s",
            port: parseInt(%(port)d)
          },
          bypassList: ["foobar.com"]
        }
      };
chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});
function callbackFn(details) {
    return {
        authCredentials: {
            username: "%(user)s",
            password: "%(pass)s"
        }
    };
}
chrome.webRequest.onAuthRequired.addListener(
            callbackFn,
            {urls: ["<all_urls>"]},
            ['blocking']
);
    """ % {
        "host": PROXY_HOST,
        "port": PROXY_PORT,
        "user": PROXY_USER,
        "pass": PROXY_PASS,
    }
    


    pluginfile = 'proxy_auth_plugin.zip'

    if not os.path.exists(pluginfile):
        with zipfile.ZipFile(pluginfile, 'w') as zp:
            zp.writestr("manifest.json", manifest_json)
            zp.writestr("background.js", background_js)

    co = Options()
    co.binary_location = config['chrome']['binary_location']
    #co.add_extension(pluginfile)
    co.add_argument('--ignore-certificate-errors')

    driver = None

    try:
        driver = webdriver.Chrome(executable_path=config['chrome']['executable_path'], chrome_options=co)
        driver.set_window_size(config['screenshot'].getint('width'), config['screenshot'].getint('height'))
        driver.get(args.url)
        print('Title: {}'.format(driver.title))

        # find the element that's name attribute is q (the google search box)
        #inputElement = driver.find_element_by_name("q")

        # type in the search
        #inputElement.send_keys("cheese!")

        # submit the form (although google automatically searches now without submitting)
        #inputElement.submit()

        # we have to wait for the page to refresh, the last thing that seems to be updated is the title
        #WebDriverWait(driver, 10).until(EC.title_contains("cheese!"))

        # You should see "cheese! - Google Search"
        #print(driver.title)

        driver.save_screenshot(args.output_file)

    finally:
        driver.quit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Visit a given URL with Chromium and save a screenshot of it.")
    parser.add_argument('url', help="The URL to visit in the browser.")
    parser.add_argument('-o', '--output-file', dest='output_file', default='screenshot.png',
        help="The file to save the screenshot to.  Defaults to screenshot.png in the current directory.")
    parser.add_argument('-c', '--config', dest='config_path', default='etc/config.ini',
        help="Configuration settings.  Defaults to etc/config.ini")
    args = parser.parse_args()

    main_chrome(args)
