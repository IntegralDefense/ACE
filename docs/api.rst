ACE API Examples
================

Let's go through a few examples using the ACE API. We will specifically use the ``ace_api`` python library.

Connect to a Server
-------------------

By default, the ``ace_api`` library will attempt to connect to `localhost`. Use the ``set_default_remote_host`` sepecify the server you want to work with.
Note that, by default, ``ace_api`` uses the OS's certificate store to validate the server. See ace_api.set_default_ssl_ca_path_ to change this behavior. 

::

        >>> import ace_api
           
        >>> server = 'ace.integraldefense.com'
           
        >>> ace_api.set_default_remote_host(server)
           
        >>> ace_api.ping()
        {'result': 'pong'}


Submitting data to ACE
----------------------

The submit (ace_api.submit_) method can be used to submit, files, data, and observables to ACE for analyis and/or correlation.


Submit a File
+++++++++++++

Say we have a suspect file in our current working director named "Business.doc" that we want to submit to ACE.
We only need to pass the name of the file with a file description to ace_api.submit_, but we will also include some tags and add a note in the details.

::

        >>> suspect_file = 'Business.doc'
        >>> import os
        >>> os.path.exists(suspect_file)
        True
        >>> suspect_file = (suspect_file, open(suspect_file, 'rb'))
            
        >>> files = []
        >>> files.append(suspect_file)
        >>> tags = ['suspect doc', 'api example']
        >>> details = {'What': 'This is an example of submitting a file for ACE to analyze, with ace_api'}
           
        >>> result = ace_api.submit('API Example: Submitting "{}" via ace_api'.format(suspect_file[0]), tags=tags, files=files, details=details)
        >>> result
        {'result': {'uuid': '8ef1bb16-934a-4419-a8fe-74380653f8c9'}}
            
        >>> uuid = result['result']['uuid']
           
        >>> result_url = 'https://{}/ace/analysis?direct={}'.format(ace_api.default_remote_host, uuid)
        >>> print("\nThe results of this submission can be viewed here: {}".format(result_url))

The results of this submission can be viewed here: https://ace.integraldefense.com/ace/analysis?direct=8ef1bb16-934a-4419-a8fe-74380653f8c9


Submit a URL
++++++++++++

Two examples of submitting a URL to ACE follows. The purpose of the first example is to demonstrate the use of directives and to open the door to the ``ace_api`` Cloudphish calls.
The second example shows how simple it is to submit a URL for analysis directly to Cloudphish.

As an observable
~~~~~~~~~~~~~~~~

You can submit as many :ref:`observables <observable>` as you desire in a submission to ACE, but they won't neccessarily get analyzed by default. This is the case for URL observables, which, require the crawl directive to tell ACE you want to analyze the URL.

Submititing a request for a suspicious URL to be analyzed, note the use of the crawl directive.::

        >>> suspicious_url = 'http://davidcizek.cz/Invoice/ifKgg-jrzA_PvC-a7'
           
        >>> tags = ['suspicious_url']
           
        >>> observables = []
        >>> observables.append({'type': 'url', 'value': suspicious_url, 'directives': ['crawl']})
           
        >>> result = ace_api.submit('Suspicious URL', tags=tags, observables=observables)
           
        >>> result
        {'result': {'uuid': 'ddb651eb-e861-41d2-8451-31b1a40fbc7e'}}
           
        >>> result_url = 'https://{}/ace/analysis?direct={}'.format(ace_api.default_remote_host, result['result']['uuid'])
        >>> print("\nHere is the alert that was made from this analysis request: {}".format(result_url))


Here is the alert that was made from this analysis request: https://ace.integraldefense.com/ace/analysis?direct=ddb651eb-e861-41d2-8451-31b1a40fbc7e

Using Cloudphish
~~~~~~~~~~~~~~~~

If you just want ACE to analyze a single URL, it's best to submit directly to Cloudphish. In this example, a URL is submitted to cloudphish that cloudphish has never seen before and a 'NEW' status is returned.
After cloudphish has finished analyzing the URL, the status changes to 'ANALYZED' and the analysis_result tells us at least one detection was found (as we alerted).

::

        >>> another_url = 'http://medicci.ru/myATT/tu8794_QcbkoEsv_Xw20pYh7ij'
        >>> cp_result = ace_api.cloudphish_submit(another_url)
           
        >>> cp_result['status']
        'NEW'
           
        >>>  # Query again, a moment later:
        ...
        >>> cp_result = ace_api.cloudphish_submit(another_url)
        >>> cp_result['status']
        'ANALYZED'
        >>> cp_result['analysis_result']
        'ALERT'
           
        >>> result_url = 'https://{}/ace/analysis?direct={}'.format(ace_api.default_remote_host, cp_result['uuid'])
        >>> print("\nThe results of this submission can be viewed here: {}".format(result_url))

The results of this submission can be viewed here: https://ace.integraldefense.com/ace/analysis?direct=732ec396-ce20-463f-82b0-6b043b07f941


Downloading Cloudphish Results
------------------------------

Cloudphish keeps a cache URL contents that can be downloaded. In this example we will download the results of the URL submitted in the previous `:ref:Using Cloudphish` example, which in this case is a malicious word document.

::

        >>> ace_api.cloudphish_download(another_url, output_path='cp_result.raw')
        True
        >>> os.path.exists('cp_result.raw')
        True


Get the status of an Analysis Request
-------------------------------------

Now, we check the status of the analysis we submitted::

        >>> result
        {'result': {'uuid': 'ddb651eb-e861-41d2-8451-31b1a40fbc7e'}}
        >>> uuid = result['result']['uuid']
            
        >>> import pprint
           
        >>> pprint.pprint(ace_api.get_analysis_status(uuid))
        {'result': {'delayed_analysis': [{'analysis_module': 'analysis_module_cloudphish',
                                  'delayed_until': '2019-01-31T21:50:57.000000',
                                  'id': 22,
                                  'insert_date': '2019-01-31T21:50:52.000000',
                                  'node_id': 1,
                                  'observable_uuid': '7de0c92b-e7ff-4099-929a-70e87b64fa56',
                                  'uuid': 'ddb651eb-e861-41d2-8451-31b1a40fbc7e'}],
            'locks': None,
            'workload': None}}
           
           
  
The above analysis status tells us that ACE is waiting on the analysis_module_cloudphish to complete its analysis.
We check again a moment later and the result tells us that ACE isn't waiting on a module to complete, there are no locks on the analysis, and nothing in the workload; hence, the analysis is complete.

:: 

        >>> pprint.pprint(ace_api.get_analysis_status(uuid))
        {'result': {'locks': None, 'delayed_analysis': [], 'workload': None}}


Get An Analysis Result
----------------------

You can get the raw ACE document showing the entire analysis (and correlation) available for a UUID.
Note, these documents can be *extremely* large. A very small part of the the document is displayed in the following example.

::

        >>> analysis = ace_api.get_analysis(uuid)
        >>> pprint.pprint(analysis)
        {'result': {'action_counters': {},
            'alerted': False,
            'analysis_mode': 'correlation',
            'company_id': 1,
            'company_name': 'default',
            'completed': True,
            'delayed': False,
            'delayed_analysis_tracking': {'analysis_module_cloudphish:7de0c92b-e7ff-4099-929a-70e87b64fa56': '2019-01-31T21:50:46.072026',
                                          'analysis_module_cloudphish:f259acb5-3835-4acd-9aba-6e2dfe177b8a': '2019-01-31T21:50:58.786645'},
            'description': 'Suspicious URL',
            'details': {'file_path': 'RootAnalysis_4baffc51-8486-4ce7-87c5-9fd6b7de9b3a.json'},
            'detections': [{'description': 'RootAnalysis(ddb651eb-e861-41d2-8451-31b1a40fbc7e) '
                                           'was tagged with suspicious_url',
                            'details': None}],
            'event_time': '2019-01-31T21:47:06.460607+0000',
            'location': 'localhost.localdomain',
            'name': None,
            'observable_store': {'0724362b-154a-4f64-b7a8-5017201b1cef': {'analysis': {'saq.modules.advanced:AdvancedLinkAnalysis': False,
                                                                                       'saq.modules.advanced:EmailLinkAnalysis': False,
                                                                                       'saq.modules.alerts:ACEAlertsAnalysis': {'alerted': False,
                                                                                                                                'completed': True,
                                                                                                                                'delayed': False,
                                                                                                                                'details': {'file_path': 'ACEAlertsAnalysis_6642399b-6026-4ac1-8242-8f0df8862e9c.json'},
                                                                                                                                'detections': [],
                                                                                                                                'observables': [],
                    ... <truncated> ...



 

ACE API
=======

Python Library
--------------

A python library exits for intereacting with the ACE API. You can install it wil pip: ``pip3 install ace_api``.

.. automodule:: ace_api 
    :members:
    :inherited-members:


Common API
----------

Alert API
---------

submit
~~~~~~
Submits a new alert to ACE. These go directly into the correlation engine for
analysis and show up to analysts as alerts.

Parameters:
alert - JSON dict with the following schema
::

    {
        'tool': tool_name,
        'tool_instance': tool_instance_name,
        'type': alert_type,
        'description': alert description,
        'event_time': time of the alert/event (in %Y-%m-%dT%H:%M:%S.%f%z format),
        'details': free-form JSON dict of anything you want to include,
        'observables': (see below),
        'tags': a list of tags to add to the alert,
    }

The observables field is a list of zero or more dicts with the following format
::

    {
        'type': The type of the observable,
        'value': The value of the observable,
        'time': The optional time of the observable (can be null),
        'tags': Optional list of tags to add to the observable,
        'directives': Optional list of directives to add to the observable,
    }

To attach files to the alert use the field named **file**.
