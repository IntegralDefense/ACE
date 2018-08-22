.. Analysis Correlation Engine documentation master file, created by
   sphinx-quickstart on Tue Aug 21 09:51:05 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

ACE: Analysis Correlation Engine
=======================================================

Release v\ |release|.

At it's core, ACE is the implementation of a detection strategy. ACE's implementation of this strategy has proven successful enough for ACE to become much more than a boom for the security analyst, it's become the foundation to an entire security ecosystem.

maybe ->

ACE is a framework for automating analyst correlation activities, in such a way, as to provide the analyst with as much information as possible at the time of alert creation. ACE treats every alert like a malicious alert, performing all of the correlation an analyst would be compelled to do.

In contrast to a siem, that will alert after certain conditions are met, ACE will take the one condition and spider out through an analysis of observables and then present that to the analyst: "This is everything that happened and this is how everything this related, what do you think?" ~ ACE to the Analyst

maybe something like this could go here too:

Just like the analyst working an alert, ACE takes every observable it finds when performing alert analysis and correlates those observables with other available data sources to reduce the analysts workload and simplify the alert by providing the analyst with as much available context as reasonably possible.


Major Features
--------------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   getting-started
   concepts
   user-guide
   admin-guide
   developer-guide


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
