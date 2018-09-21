Administration Guide
====================


Concepts
--------

There are several concepts crucial to understanding how ACE works and how to use ACE. For the analyst, it’s important to understand observables, tagging, and dispositioning. The administrator and developer needs to understand those concepts as well, but additionally must understand ACE’s dependencies and its engine and modular architecture.

Engines
+++++++

The ACE system is named after the system's core engine, the Analysis Correlation *Engine*. However, there are additional engines that interface with, utilize, or provide input to the core Analysis Correlation Engine. Below is a table of the currently defined engines:

+---------------+--------------------------------------------------------------------------------------------------------------+
|   Engine      |                                       Description                                                            |
+===============+==============================================================================================================+
| ace           | The Alert Correlation Engine creates and submits alerts to the Analysis Correlation Engine                   |
+---------------+--------------------------------------------------------------------------------------------------------------+
| carbon_black  | Collects binaries and files from CarbonBlack environments and runs them through ACE                          |
+---------------+--------------------------------------------------------------------------------------------------------------+
| brotex_stream | Responsible for analyzing tar files extracted from SMTP and HTTP streams via the Brotex system [#]_.         |
|               | Extracted emails are submitted to the Email Scanning Engine. Extracted HTTP streams are submitted to the     |
|               | HTTP Scanning Engine.                                                                                        |
+---------------+--------------------------------------------------------------------------------------------------------------+
| email_scanner | The Email Scanning Engine is configured to fully analyze and scan emails from any available source. There is |
|               | special support for emails submitted from Office365 (which includes the actual email as an attachment inside |
|               | the email). The two sources of input for the Email Scanning Engine are the emails parsed out of tar files    |
|               | from the Brotex Engine, which are submitted via local filesystem, and emails collected from the ACE Mailbox  |
|               | Client systems [#]_, which are submitted via custom SSL connections. Emails that have any alert-able         |
|               | properties are submitted to the Alert Correlation Engine.                                                    |
+---------------+--------------------------------------------------------------------------------------------------------------+
| http_scanner  | Processes and scans individual HTTP requests for malicious content. Alert-able requests are submitted to the |
|               | Alert Correlation Engine.                                                                                    |
+---------------+--------------------------------------------------------------------------------------------------------------+
| cloudphish    | Processes, analyzes, crawls, and scans content pulled from received URLs. Maintains a cache of results and a |
|               | URL whitelisting system. Alert-able URLs are sent to the Alert Correlation Engine. Cloudphish has an API.    | 
+---------------+--------------------------------------------------------------------------------------------------------------+

.. [#] See the Brotex systems on IntegralDefense's github page: https://github.com/IntegralDefense
.. [#] The ACE Mailbox Client is open sourced at https://github.com/IntegralDefense/amc.git


Modules
+++++++

ACE modules automate something that an analyst has previously done manually. These modules do all "the work" on observables; each module knows which types of observables it works with and "knows what to do" with those observables. Modules can be built to do anything that you can automate. Each ACE engine knows which ACE modules to work with, and modules can perform work for many different engines.

... More to come here.

Recursive Correlation & Analysis
++++++++++++++++++++++++++++++++

.. role:: strike
   :class: strike

This whole section should probably be deleted. It's covered elsewhere now.

With the introduction of observables, engines, and modules, you can begin to understand how ACE performs its recursive analysis and correlation.  

For example, given observable type 'file', each ACE module that acts on an observable of type file will be called to perform its analysis.  From the output of each module’s analysis, ACE will discover and create new observables, which, kicks off more modules to perform analysis.  This recursive process will continue until all observables are discovered, analyzed, and correlated, or, until a specified alert correlation timeout is reached. ACE’s default timeout limit for recursive alert analysis is 15 minutes, however, a warning will be logged if alert analysis exceeds five minutes. These values are configurable. 

