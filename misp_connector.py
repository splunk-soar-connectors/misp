# --
# File: misp_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

# Imports local to this App
import requests
import json
from bs4 import BeautifulSoup
from pymisp import PyMISP


class MispConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_CREATE_EVENT = "create_event"
    ACTION_ID_ADD_ATTRIBUTES = "add_attributes"

    def __init__(self):

        # Call the BaseConnectors init first
        super(MispConnector, self).__init__()
        self._verify = None
        self._event = None

    def _validate_ip(self, input_data):

        ips = []
        # First work on the comma as the seperator
        if (',' in input_data):
            ips = input_data.split(',')
        elif(';' in input_data):
            ips = input_data.split(';')

        for ip in ips:
            if (not ph_utils.is_ip(ip.strip())):
                return False
        return True

    def _validate_domain(self, input_data):

        domains = []
        # First work on the comma as the seperator
        if (',' in input_data):
            domains = input_data.split(',')
        elif(';' in input_data):
            domains = input_data.split(';')

        for domain in domains:
            if (not ph_utils.is_domain(domain.strip())):
                return False
        return True

    def _validate_email(self, input_data):

        emails = []
        # First work on the comma as the seperator
        if (',' in input_data):
            emails = input_data.split(',')
        elif(';' in input_data):
            emails = input_data.split(';')

        for email in emails:
            if (not ph_utils.is_email(email.strip())):
                return False
        return True

    def initialize(self):

        config = self.get_config()
        self._verify = config.get("verify_server_cert")
        self._misp_url = config.get("base_url")
        api_key = config.get("api_key")

        self.save_progress("Creating MISP API session...")
        try:
            self._misp = PyMISP(self._misp_url, api_key, self._verify, 'json')
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Failed to create API session:", e)

        self.set_validator('ip', self._validate_ip)
        self.set_validator('domain', self._validate_domain)
        self.set_validator('email', self._validate_email)

        return phantom.APP_SUCCESS

    def _test_connectivity(self):
        action_result = self.add_action_result(ActionResult())
        self.save_progress("Checking connectivity to your MISP instance...")
        config = self.get_config()
        auth = {"Authorization": config.get("api_key")}
        ret_val, resp_json = self._make_rest_call('/servers/getPyMISPVersion.json', action_result, headers=auth)
        if phantom.is_fail(ret_val):
            self.append_to_message('Test connectivity failed')
            return self.get_status()
        else:
            self.debug_print("In test connectivity, just before returning")
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity to MISP was successful.")

    def _create_event(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            self._event = self._misp.new_event(distribution=param["distribution"], threat_level_id=param["threat_level_id"],
                                         analysis=param["analysis"], info=param["info"])
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Failed to create MISP event:", e)

        action_result.add_data(self._event["Event"])
        action_result.set_summary({"message": "Event created with id: {0}".format(self._event["Event"]["id"])})

        addAttributes = param.get("add_attributes")
        if addAttributes is True:
            try:
                self._perform_adds(param, action_result)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Failed to add attributes to newly created MISP event:", e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _perform_adds(self, param, result, add_data=False):

        source_ips = param.get("source_ips")
        if source_ips is not None:
            try:
                src_ip_list = phantom.get_list_from_string(source_ips)
                for ip in src_ip_list:
                    source_ip_attribute = self._misp.add_ipsrc(event=self._event, ipsrc=ip, to_ids=param["to_ids"])
                    if add_data is True:
                        result.add_data(source_ip_attribute["Attribute"])

            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Failed to add source IP attribute:", e)

        dest_ips = param.get("dest_ips")
        if dest_ips is not None:
            try:
                dst_ip_list = phantom.get_list_from_string(dest_ips)
                for ip in dst_ip_list:
                    dest_ip_attribute = self._misp.add_ipdst(event=self._event, ipdst=ip, to_ids=param["to_ids"])
                    if add_data is True:
                        result.add_data(dest_ip_attribute["Attribute"])
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Failed to add dest IP attribute:", e)

        source_emails = param.get("source_emails")
        if source_emails is not None:
            try:
                source_email_list = phantom.get_list_from_string(source_emails)
                for email in source_email_list:
                    source_email_attribute = self._misp.add_email_src(event=self._event, email=email, to_ids=param["to_ids"])
                    if add_data is True:
                        result.add_data(source_email_attribute["Attribute"])
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Failed to add source email attribute:", e)

        dest_emails = param.get("dest_emails")
        if dest_emails is not None:
            try:
                dest_email_list = phantom.get_list_from_string(dest_emails)
                for email in dest_email_list:
                    dest_email_attribute = self._misp.add_email_dst(event=self._event, email=email, to_ids=param["to_ids"])
                    if add_data is True:
                        result.add_data(dest_email_attribute["Attribute"])
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Failed to add dest email attribute:", e)

        domains = param.get("domains")
        if domains is not None:
            try:
                domain_list = phantom.get_list_from_string(domains)
                for domain in domain_list:
                    domain_attribute = self._misp.add_domain(event=self._event, domain=domain,
                                                           to_ids=param["to_ids"])
                    if add_data is True:
                        result.add_data(domain_attribute["Attribute"])
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Failed to add domain attribute:", e)

    def _add_attributes(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._event is None:
            try:
                self._event = self._misp.get_event(event_id=param["event_id"])
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Failed to get event for adding attributes:", e)

        try:
            self._perform_adds(param, action_result, add_data=True)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Failed to add attributes to newly created MISP event:", e)
        action_result.set_summary({"message": "Attributes added to event: {0}".format(self._event["Event"]["id"])})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON", e), None

        if (200 <= r.status_code < 205):
            return phantom.APP_SUCCESS, resp_json

        action_result.add_data(resp_json)
        message = r.text.replace('{', '{{').replace('}', '}}')
        return action_result.set_status(phantom.APP_ERROR,
                                               "Error from server, Status Code: {0} data returned: {1}".format(
                                                   r.status_code, message)), resp_json

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if (r is not None):
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
                action_result.add_debug_data({'r_status_code': r.status_code})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})

        # There are just too many differences in the response to handle all of them in the same function
        if ('json' in r.headers.get('Content-Type', '')):
            return self._process_json_response(r, action_result)

        if ('html' in r.headers.get('Content-Type', '')):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        # if (200 <= r.status_code < 205) and (not r.text):
        #   return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, endpoint, result, headers={}, params={}, json={}, method="get"):

        url = "{0}{1}".format(self._misp_url, endpoint)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None
        except Exception as e:
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(str(e))), None

        try:
            r = request_func(url, params=params, json=json, headers=headers, verify=self._verify)
        except Exception as e:
            return result.set_status(phantom.APP_ERROR, "REST API to server failed: ", e), None

        return self._process_response(r, result)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_CREATE_EVENT):
            ret_val = self._create_event(param)
        if (action_id == self.ACTION_ID_ADD_ATTRIBUTES):
            ret_val = self._add_attributes(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = MispConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
