.. Analysis Correlation Engine documentation master file, created by
   sphinx-quickstart on Tue Aug 21 09:51:05 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

ACE: Analysis Correlation Engine
=======================================================

Release v\ |release|.

ACE is a detection system and automation framework. ACE’s foundation is its Engine for recursive analysis, but also its intuitive presentation to the human analyst.

Send your Alerts to ACE, and let ACE handle the ordinary, manual, redundant, and repetitive tasks of collecting, combining, and relating data. ACE will then contextually and intuitively present all the right data to the human, allowing for a quick, high confidence determination to be made.

Got some new analysis that can be automated? Awesome! Add your automation, and let ACE keep working for you.


.. figure:: _static/recursive-analysis-and-contextual-presentation.png
   :align: center

   Recursive Analysis; Presentation

ACE **is NOT** a SIEM... but, it *kind of*, *sort of* can act like one, if that's your thing.

For the most part, custom hunting tools send Alerts to ACE using ACE’s client library (API wrapper). ACE then gets to work by taking whatever one single detectable condition it’s given, and spirals out through its recursive analysis of observables; hitting as many detections points as possible across the attack surface.

ACE **is** ..

* an email scanner
* a detection tool set and platform
* an automation framework
* a recursive file scanner
* a URL crawler and cacher
* a system for automated, recursive, data analysis and correlation
* more things that could be added to this list...

Built for the information security team, ACE is the implementation of a proven detection strategy, a framework for automating analysis, a central platform to launch and manage incident response activates, an email scanner, and much more.

egardless of skill level, ACE greatly reduces the time it takes an analyst to make a high confidence determination, or as we call it, disposition. This reduction in time-to-disposition, coupled with the appropriate hunting and tuning mindset, means that security teams can greatly increase the attack surface they cover, all while utilizing the same amount of analyst time and practically eliminating alert fatigue. Optimization good, alert fatigue bad.

Major Features
--------------

+ Email Scanning
+ Recursive File Scanning
+ URL Crawling and Content Caching
+ Intuitive Alert Presentation
+ Recursive Data Analysis & Correlation
+ Central Analyst Interface
+ Event management
+ Intel Ingestion
+ Modular Design for extending automation

.. image:: _static/analyst_on_ace.png

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   installation
   analyst-orientation
   education 
   additional
   admin-guide
   developer-guide


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
