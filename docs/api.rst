ACE API
=======

Common API
----------

Alert API
---------

submit
~~~~~
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
