# --
# File: misp_connector.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.utils as ph_utils

# Imports local to this App
import json
import requests
from bs4 import BeautifulSoup
from pymisp import PyMISP


# This patching is required because the PyMISP API sets the verify flag as a
#  member of the Session object (Session.verify)
# Whether its a bug or just because it's an older version, the requests module
#  on phantom doesn't do anything if that member is set, and will only ignore
#  server verification if its passed as part of the function
def patch_requests():
    __orig_session_get = requests.Session.get
    __orig_session_post = requests.Session.post

    def get(self, *args, **kwargs):
        if self.verify is not None:
            kwargs.pop('verify', None)
        else:
            self.verify = True
        return __orig_session_get(self, verify=self.verify, *args, **kwargs)

    def post(self, *args, **kwargs):
        if self.verify is not None:
            kwargs.pop('verify', None)
        else:
            self.verify = True
        return __orig_session_post(self, verify=self.verify, *args, **kwargs)

    requests.Session.get = get
    requests.Session.post = post


def slice_list(lst, max_results):
    if max_results > 0:
        return lst[:max_results]
    else:
        return lst[max_results:]


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class MispConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_CREATE_EVENT = "create_event"
    ACTION_ID_ADD_ATTRIBUTES = "add_attributes"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_GET_EVENT = "get_event"

    def __init__(self):

        # Call the BaseConnectors init first
        super(MispConnector, self).__init__()
        self._verify = None
        self._event = None

    def _validate_ip(self, input_data):

        ips = []
        # First work on the comma as the seperator
        if type(input_data) is list:
            ips = input_data
        elif (',' in input_data):
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

    def _validate_url(self, input_data):

        urls = []
        # First work on the comma as the seperator
        if (',' in input_data):
            urls = input_data.split(',')
        elif(';' in input_data):
            urls = input_data.split(';')

        for url in urls:
            if (not ph_utils.is_url(url.strip())):
                return False
        return True

    def _validate_indicator(self, input_data, inc_type):

        incs = []
        if type(input_data) is list:
            incs = input_data
        elif (',' in input_data):
            incs = input_data.split(',')
        elif(';' in input_data):
            incs = input_data.split(';')

        for inc in incs:
            if inc_type == "ip":
                if (not ph_utils.is_ip(inc.strip())):
                    return False
            elif inc_type == "email":
                if (not ph_utils.is_email(inc.strip())):
                    return False
            elif inc_type == "domain":
                if (not ph_utils.is_domain(inc.strip())):
                    return False
            elif inc_type == "url":
                if (not ph_utils.is_url(inc.strip())):
                    return False
        return True

    def initialize(self):

        patch_requests()
        config = self.get_config()
        self._verify = config.get("verify_server_cert", False)
        self._misp_url = config.get("base_url")
        api_key = config.get("api_key")

        self.save_progress("Creating MISP API session...")
        try:
            self._misp = PyMISP(self._misp_url, api_key, ssl=self._verify)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Failed to create API session:", e)

        self.set_validator('ip', self._validate_ip)
        self.set_validator('domain', self._validate_domain)
        self.set_validator('email', self._validate_email)
        self.set_validator('url', self._validate_url)

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
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Test Connectivity Passed")

    def _create_event(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        distrib_map = {
            'your org only': 0,
            'this community only': 1,
            'connected communities': 2,
            'all communities': 3,
            'sharing group': 4,
            '0': 0,
            '1': 1,
            '2': 2,
            '3': 3,
            '4': 4
        }
        tli_map = {
            'high': 1,
            'medium': 2,
            'low': 3,
            'undefined': 4,
            '1': 1,
            '2': 2,
            '3': 3,
            '4': 4
        }
        analysis_map = {
            'initial': 0,
            'ongoing': 1,
            'completed': 2,
            '0': 0,
            '1': 1,
            '2': 2
        }

        try:
            distribution = distrib_map[str(param['distribution']).lower()]
            threat_level_id = tli_map[str(param['threat_level_id']).lower()]
            analysis = analysis_map[str(param['analysis']).lower()]
        except KeyError as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid string in parameter: {}".format(str(e)))

        try:
            self._event = self._misp.new_event(threat_level_id=threat_level_id, distribution=distribution,
                                         analysis=analysis, info=param["info"])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Failed to create MISP event:", e)

        action_result.add_data(self._event["Event"])
        action_result.set_summary({"message": "Event created with id: {0}".format(self._event["Event"]["id"])})

        addAttributes = param.get("add_attributes")
        if addAttributes is True:
            ret_val = self._perform_adds(param, action_result, add_data=True)
            if phantom.is_fail(ret_val):
                return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_indicator(self, indicator_list, action_result, indicator_type, to_ids, add_data=False):
        for indicator in indicator_list:
            if indicator_type == "source_ips":
                indicator_attribute = self._misp.add_ipsrc(event=self._event, ipsrc=indicator, to_ids=to_ids)
            elif indicator_type == "dest_ips":
                indicator_attribute = self._misp.add_ipdst(event=self._event, ipdst=indicator, to_ids=to_ids)
            elif indicator_type == "domains":
                indicator_attribute = self._misp.add_domain(event=self._event, domain=indicator, to_ids=to_ids)
            elif indicator_type == "source_emails":
                indicator_attribute = self._misp.add_email_src(event=self._event, email=indicator, to_ids=to_ids)
            elif indicator_type == "dest_emails":
                indicator_attribute = self._misp.add_email_dst(event=self._event, email=indicator, to_ids=to_ids)
            elif indicator_type == "urls":
                indicator_attribute = self._misp.add_url(event=self._event, url=indicator, to_ids=to_ids)
            else:
                try:
                    indicator_attribute = self._misp.add_named_attribute(
                        event=self._event, type_value=indicator_type, value=indicator, to_ids=to_ids
                    )
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Failed to update MISP event:", e)

            if add_data is True:
                indicator_attribute["Attribute"]["attribute_id"] = indicator_attribute["Attribute"]["id"]
                action_result.add_data(indicator_attribute["Attribute"])

    def _perform_adds(self, param, action_result, add_data=False):

        default_indicator_list = [
            'source_ips', 'dest_ips',
            'domains', 'urls',
            'dest_emails', 'source_emails'
        ]

        for i in default_indicator_list:
            val = param.get(i)
            if val:
                if type(val) is list:
                    indicator_list = val
                else:
                    indicator_list = phantom.get_list_from_string(val)

                try:
                    self._add_indicator(indicator_list, action_result, i, param.get('to_ids', False), add_data=add_data)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error adding attribute to MISP event: {}".format(str(e)))

        json_str = param.get('json')
        if json_str:
            try:
                d = json.loads(json_str)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Invalid JSON parameter. Error: {}".format(str(e)))
            for k, v in d.items():
                if type(v) is list:
                    indicator_list = v
                else:
                    if "," in str(v):
                        indicator_list = phantom.get_list_from_string(str(v))
                    else:
                        indicator_list = list(str(v))
                try:
                    self._add_indicator(indicator_list, action_result, k, param.get('to_ids', False), add_data=add_data)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error adding attribute to MISP event: {}".format(str(e)))
        return phantom.APP_SUCCESS

    def _add_attributes(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._event is None:
            try:
                self._event = self._misp.get_event(event_id=param["event_id"])
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Failed to get event for adding attributes:", e)

        ret_val = self._perform_adds(param, action_result, add_data=True)
        if phantom.is_fail(ret_val):
            return ret_val
        if self._event.get('Event', {}).get('id', ""):
            action_result.set_summary({"message": "Attributes added to event: {0}".format(self._event["Event"]["id"])})
        else:
            return action_result.set_status(phantom.APP_ERROR, "Failed to get event '{0}' for adding attributes".format(param["event_id"]))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _do_search(self, action_result, **kwargs):
        try:
            resp = self._misp.search(**kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, e), None)

        return RetVal(phantom.APP_SUCCESS, resp)

    def _run_query(self, param):
        action_result = self.add_action_result(ActionResult(param))
        query_dict = {}
        controller = param['controller']
        query_dict['controller'] = controller
        if 'event_id' in param:
            if ',' in param['event_id']:
                query_dict['eventid'] = param['event_id'].split(',')
            else:
                query_dict['eventid'] = param['event_id']
        if 'tags' in param:
            if ',' in param['tags']:
                query_dict['tags'] = param['tags'].split(',')
            else:
                query_dict['tags'] = param['tags']
        if 'other' in param:
            try:
                query_dict.update(json.loads(param['other']))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON object", e)

        try:
            max_results = int(param.get('max_results', 10))
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "The value of max results must be an integer")

        ret_val, response = self._do_search(action_result, **query_dict)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if max_results:
            if controller == 'events':
                if response['response']:
                    response['response'] = slice_list(response['response'], max_results)
            else:
                if response['response']:
                    response['response']['Attribute'] = slice_list(response['response']['Attribute'], max_results)

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully ran query")

    def _download_malware_samples(self, action_result, event_id):
        """ Download malware samples for an event """
        try:
            resp = self._misp.download_samples(event_id=event_id)
        except Exception as e:
            return action_result.set_status("Error getting attachments from event", e)

        # 'resp' is a tuple that looks like this:
        # (Success_bool, [[event_id, file_name, bytes], [...],...])

        if not resp[0]:
            return phantom.APP_SUCCESS  # No Attachments

        for sample in resp[1]:
            if hasattr(Vault, 'get_vault_tmp_dir'):
                file_path = Vault.get_vault_tmp_dir() + '/' + sample[1]
                Vault.create_attachment(file_path, self.get_container_id(), file_name=sample[1])
            else:
                file_path = '/vault/tmp/' + sample[1]
                with open(file_path, 'wb') as fp:
                    fp.write(sample[2].read())
                    fp.close()
                    Vault.add_attachment(file_path, self.get_container_id(), file_name=sample[1])

        return phantom.APP_SUCCESS

    def _get_attachments(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        event_id = param['event_id']
        query_dict = {}
        query_dict['eventid'] = event_id
        query_dict['controller'] = 'attributes'

        ret_val, attachments = self._do_search(action_result, **query_dict)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param.get('download_samples'):
            # Don't forget about this
            self._download_malware_samples(action_result, event_id)

        action_result.add_data(attachments)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved attributes")

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
        elif (action_id == self.ACTION_ID_ADD_ATTRIBUTES):
            ret_val = self._add_attributes(param)
        elif (action_id == self.ACTION_ID_RUN_QUERY):
            ret_val = self._run_query(param)
        elif (action_id == self.ACTION_ID_GET_EVENT):
            ret_val = self._get_attachments(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = MispConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
