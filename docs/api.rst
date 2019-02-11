ACE API Examples
================

Let's go through a few examples using the ACE API. We will specifically use the ``ace_api`` python library.

Connect to a Server
-------------------

By default, the ``ace_api`` library will attempt to connect to `localhost`. Use the :func:`ace_api.set_default_remote_host` function to have the library connect to a different server.
The OS's certificate store is used to validate the server. See :func:`ace_api.set_default_ssl_ca_path` to change this behavior. 

::

        >>> import ace_api
           
        >>> server = 'ace.integraldefense.com'
           
        >>> ace_api.set_default_remote_host(server)
           
        >>> ace_api.ping()
        {'result': 'pong'}

You can over-ride this default in the :func:`ace_api.Analysis` class with the :func:`ace_api.Analysis.set_remote_host` method and you can also manually specify a remote host with any submit.

::

        >>> analysis = ace_api.Analysis('this is the analysis description')

        >>> analysis.remote_host
        'ace.integraldefense.com'

        >>> analysis.set_remote_host('something.else.com').remote_host
        'something.else.com' 

        >>> ace_api.default_remote_host
        'ace.integraldefense.com'

If your ACE instance is listening on a port other than 443, specify it like so::

        >>> ace_api.set_default_remote_host('ace.integraldefense.com:24443')

        >>> ace_api.default_remote_host
        'ace.integraldefense.com:24443'

Submitting data to ACE
----------------------

You should submit data to ace by first creating an Analysis_ object and loading it with the data you want to submit for analysis and/or correlation.
The below examples show how to perform some common submissions.


Submit a File
~~~~~~~~~~~~~

Say we have a suspect file in our current working director named "Business.doc" that we want to submit to ACE.
First, we create an analysis object and then we pass the path to the file to the :func:`ace_api.Analysis.add_file` method.
We will also include some tags and check the status (:func:`ace_api.Analysis.status`) of the analysis as ACE works on the submission.

::

        >>> path_to_file = 'Business.doc'
        
        >>> analysis.add_file(path_to_file)
        <ace_api.Analysis object at 0x7f23d57e74e0>
        
        >>> analysis.add_tag('Business.doc').add_tag('suspicious doc')
        <ace_api.Analysis object at 0x7f23d57e74e0>

        >>> analysis.submit()
        <ace_api.Analysis object at 0x7f23d57e74e0>

        >>> analysis.status
        'NEW'

        >>> analysis.status
        'ANALYZING'

        >>> analysis.status
        'COMPLETE (Alerted with 8 detections)'

        >>> result_url = 'https://{}/ace/analysis?direct={}'.format(analysis.remote_host, analysis.uuid)

        >>> print("\nThe results of this submission can be viewed here: {}".format(result_url))

The results of this submission can be viewed here: https://ace.integraldefense.com/ace/analysis?direct=137842ac-9d53-4a25-8066-ad2a1f6cfa17

Submit a URL
~~~~~~~~~~~~

Two examples of submitting a URL to ACE follow. The first example shows how to submit a URL by adding the URL as an observable to an Analysis_ object. This also allows us to demontrate the use of directives.
The second example shows how simple it is to submit a URL for analysis directly to Cloudphish.

As an observable
++++++++++++++++

You can submit as many :ref:`observables <observable>` as you desire in a submission to ACE, but they won't neccessarily get passed to every analysis module that can work on them by default. This is the case for URL observables, which by themselves, require the crawl directive to tell ACE you want to download the conent from the URL for further analysis.

Submititing a request for a suspicious URL to be analyzed, note the use of the crawl directive and how to get a list of the valid directives.

::

        >>> suspicious_url = 'http://davidcizek.cz/Invoice/ifKgg-jrzA_PvC-a7'

        >>> analysis = ace_api.Analysis('Suspicious URL')

        >>> analysis.add_tag('suspicious_url')
        <ace_api.Analysis object at 0x7f23d57e7588>
         
        >>> for d in ace_api.get_valid_directives()['result']:
        ...     if d['name'] == 'crawl':
        ...         print(d['description'])
        ... 
        crawl the URL

        >>> analysis.add_url(suspicious_url, directives=['crawl']).submit()
        <ace_api.Analysis object at 0x7f23d57e7588>

        >>> analysis.status
        'COMPLETE (Alerted with 9 detections)'

        >>> result_url = 'https://{}/ace/analysis?direct={}'.format(analysis.remote_host, analysis.uuid)
         
        >>> print("\nThe results of this submission can be viewed here: {}".format(result_url))

The results of this submission can be viewed here: https://ace.integraldefense.com/ace/analysis?direct=de66b2d3-f273-4bdd-a05b-771ecf5c8a76

Using Cloudphish
++++++++++++++++

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

Cloudphish keeps a cache of the URL content it downloads. In this example we will download the results of the URL submitted in the previous example, which in this case is a malicious word document.

::

        >>> ace_api.cloudphish_download(another_url, output_path='cp_result.raw')
        True
        >>> os.path.exists('cp_result.raw')
        True

Downloading an Alert
--------------------

You can use the :func:`ace_api.download` function to download an entire Alert. Below, we download an entire Alert and have it written to a directory named by the Alert's UUID.::

        >>> uuid = cp_result['uuid']

        >>> >>> uuid
        '732ec396-ce20-463f-82b0-6b043b07f941'

        >>> ace_api.download(uuid, target_dir=uuid)

Now, there is a new directory named '732ec396-ce20-463f-82b0-6b043b07f941' in our current working directory that contians all of the files and data from the alert with uuid 732ec396-ce20-463f-82b0-6b043b07f941. Use the :func:`ace_api.load_analysis` function to load an alert into a new Analysis_ object.


ACE API
=======

Python Library
--------------

A python library exits for intereacting with the ACE API. You can install it wil pip: ``pip3 install ace_api``.

.. _Analysis:

.. autoclass:: ace_api.Analysis
    :members:

.. autofunction:: ace_api.set_default_remote_host

.. autofunction:: ace_api.set_default_ssl_ca_path

.. autofunction:: ace_api.get_supported_api_version

.. autofunction:: ace_api.get_valid_observables

.. autofunction:: ace_api.get_valid_directives

.. autofunction:: ace_api.get_analysis

.. autofunction:: ace_api.load_analysis

.. autofunction:: ace_api.download

.. autofunction:: ace_api.upload

.. autofunction:: ace_api.cloudphish_download

.. autofunction:: ace_api.cloudphish_submit

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
