# Python Bindings for ACE REST API

## Examples

### Connect to a Server

Setting the default remote host:

        >>> import ace_api
           
        >>> server = 'ace.integraldefense.com'
           
        >>> ace_api.set_default_remote_host(server)
           
        >>> ace_api.ping()
        {'result': 'pong'}

Setting the remote host for an Analysis class:

        >>> analysis = ace_api.Analysis('this is the analysis description')

        >>> analysis.set_remote_host('something.else.com').remote_host
        'something.else.com' 

If your ACE instance is listening on a port other than 443, specify it like so::

        >>> ace_api.set_default_remote_host('ace.integraldefense.com:24443')

        >>> ace_api.default_remote_host
        'ace.integraldefense.com:24443'

### Submit a File to ACE

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

### Submit a URL to Cloudphish

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

## Documentation

ACE's API documentation: 

View ACE's full documentation here: [https://ace-analysis.readthedocs.io/en/latest/](https://ace-analysis.readthedocs.io/en/latest/)
