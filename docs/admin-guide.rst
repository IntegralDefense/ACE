.. _admin-guide:

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


Recursive Analysis
++++++++++++++++++

.. role:: strike
   :class: strike

With the introduction of observables, engines, and modules, you can begin to understand how ACE performs its recursive analysis and correlation.  

For example, given observable type 'file', each ACE module that acts on an observable of type file will be called to perform its analysis.  From the output of each module’s analysis, ACE will discover and create new observables, which, kicks off more modules to perform analysis.  This recursive process will continue until all observables are discovered, analyzed, and correlated, or, until a specified alert correlation timeout is reached. ACE’s default timeout limit for recursive alert analysis is 15 minutes, however, a warning will be logged if alert analysis exceeds five minutes. These values are configurable under ACE's 'global' configuration section.


Turning on Engines
------------------

When installed, ACE likely started several engines and modules by default. Almost certainly, the correlation engine was started. You can see below how to stop and start several different engines and modules. If you want to try and start all engines at the same time, the following command will accomplish that::

  $ /opt/ace/bin/start-ace

Correlation Engine
++++++++++++++++++

The correlation engine is essential::

  $ /opt/ace/bin/start-correlation-engine

.. _email-scanning:

Email Scanner
+++++++++++++

The email scanning engine will detect any file observable that is compliant with rfc822.

::

  $ /opt/ace/bin/start-email-scanning-engine

CloudPhish
++++++++++

Make sure **engine_cloudphish** is enabled in ``saq.ini``. You may need to add the following enabled variable::

  [engine_cloudphish]
  enabled = yes

Also in ``saq.ini``, make sure the following config item has this value; unless you know your situation is different. You may have to create this section::

  [analysis_module_cloudphish]
  cloudphish.1 = https://localhost/ace/cloudphish

The CloudPhish engine depend on the CrawlPhish analysis module. So make sure the **analysis_module_crawlphish** is turned on in ``saq.ini``. You may have to create this section:: 

    [analysis_module_crawlphish]
    enabled = yes

Next, make sure the following three files exist. Example content is given for each file. First, ``/opt/ace/etc/crawlphish.whitelist``::

    # url shorteners and more
    anonfile.xyz
    bit.ly
    goo.gl
    ow.ly
    is.gd
    dd.tt
    dropbox.com
    tinyurl.com
    zip.net
    drive.google.com
    wetransfer.com
    hyperurl.co
    1drv.ms
    onedrive.live.com
    amazonaws.com

Second, ``etc/crawlphish.path_regex:``::

    # possible file extensions for trojans
    \.(pdf|zip|scr|js|cmd|bat|ps1|doc|docx|xls|xlsx|ppt|pptx|exe|vbs|vbe|jse|wsh|cpl|rar|ace|hta)$

Finally, ``etc/crawlphish.blacklist``::

    # ignore loopback
    127.0.0.1
    # RFC 1918
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    # put more domains and IPs you want to avoide

Finally, everything is ready to turn on the cloudphish engine::

  $ bin/start-cloudphish


Enabling Modules
----------------

Yara Scanner
++++++++++++

First, make sure the **analysis_module_yara_scanner_v3_4** section in ``/opt/ace/etc/saq.ini`` is enabled. Then create a ``/opt/signatures`` directory::

  $ mkdir /opt/signatures
  $ cd /opt/signatures
  
Now place your yara signature directories in `/opt/signatures/<your yara directories>`.

Create a symlink for ACE to find your signatures::

  $ ln -s /opt/signatures $SAQ_HOME/etc/yara

Start the yara module::

  $ /opt/ace/bin/start-yss

Live Renderer
+++++++++++++

The live browser rendering module will try to render a png image of any html file it's given. This can be particularly helpful for viewing email html content. Keep security in-mind when implementing this module.

To configure the module, execute the following commands. NOTE: The following instructions explain how to set up the renderer on localhost, but you can set up the rendered on a dedicated server as well.

Create a user named "cybersecurity"::

  $ sudo adduser cybersecurity

Generate a ssh key as the ace user::

  $ ssh-keygen -t rsa -b 4096

Add this entry to your ace ssh config::

  $ cd /home/ace
  $ vim .ssh/config

  Host render-server
    HostName localhost
    port 22
    User cybersecurity
    IdentityFile /home/ace/.ssh/id_rsa

Set up the cybersecurity account::

  $ sudo su - cybersecurity
  $ cd && mkdir .ssh && mkdir tmp
  $ cat /home/ace/.ssh/id_rsa.pub >> .ssh/authorized_keys
  $ ln -s /opt/ace/render render
  $ exit

Add localhost as a known ssh host for the ace user::

  $ ssh-keyscan -H localhost >> .ssh/known_hosts

Run the ``install`` script::

  $ cd /opt/ace/render/ && ./install

Download the most recent Chrome driver from https://sites.google.com/a/chromium.org/chromedriver/downloads::

  $ cd /opt/ace/render 
  $ wget https://chromedriver.storage.googleapis.com/<version number goes here>/chromedriver_linux64.zip
  $ unzip chromedriver_linux64.zi

Finally, make sure the following (at a minimum) is in your ``saq.ini`` file::

  [analysis_module_live_browser_analyzer]
  remote_server = render-server
  enabled = yes

Now, restart the correlation engine and render away.
