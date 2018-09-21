.. It might make sense to have a the high-level (super fast) how-to at the
   top, under installation, but then make each step links to a more detailed
   sub-section breaking down each step


Installation + Adding Data
==========================

Super fast How-To
-----------------

#. Clean Ubuntu 18 install.
#. Create username/group ace/ace.
#. Add ace to sudo.
#. Login as user ace.
#. `sudo mkdir /opt/ace && sudo chown ace:ace /opt/ace && cd /opt/ace`
#. `git clone https://github.com/IntegralDefense/ACE.git .`
#. `./installer/source_install`
#. `source load_environment`
#. `./ace add-user username email_address`
#. Goto https://127.0.0.1:5000/ace/ or whatever IP address you're using.

Detailed Installation
---------------------

.. _get-data-in:

Getting Data into ACE
---------------------

Manual Analysis
+++++++++++++++

Via the Manual Analysis page, an analyst can submit an observable for ACE to analyze.

.. _manual-analysis-page:
.. figure:: _static/gui-manual-analysis.png

   Observables can be submitted for analysis via the Manual Analysis page

By default, the Insert Date is set to the current time, and the Description is set to 'Manual Correlation'. You can change the description to something meaningful. The Target Company will also be set to default, which should be fine for most ACE installations.

Select the type of observable you wish to correlate and then provide the value. Click the Add button to correlate more than one observable type and/or value at a time.

Shortly after you've submitted your observable(s) for correlation, you will see your alert appear on the Manage Alerts page with the description you provided. The alert status will change to 'Complete' once ACE is finished performing its analysis. You must currently refresh the Manage Alerts page to see the alert status updates.
