Additional Features
===================

The following are additional ACE features that are not necessary to understand when orienting an analyst with ACE or didn't quite fit in other areas of the documentation. If you're here, it's assumed that you're familiar with the content in the :ref:`Getting Data into ACE <get-data-in>` and :ref:`Analyst Orientation <analyst-orientation>` sections.

Events
------

An event in ACE is a collection of related alerts that require some response activities from your analysts. For example, you can add several phish alerts that have the same malicious attachment to an event. The event denotes that your analysts have some follow-up work to do on the alerts, such as remediating the email to remove it from the user's inbox or ensuring the user did not click any malicious links or open any malicious files.

We developed a sister project called `Event Sentry <https://github.com/IntegralDefense/eventsentry>`_ that monitors ACE for events that were created and automatically creates comprehensive wiki write-ups of the event. Other features of Event Sentry include:

  - Detects types of malware using built-in and extendable detection modules.
  - Detects kill chain phase by determining if a user clicked a link, submitted credentials, or opened a malware sample.
  - Extracts indicators from e-mails, sandbox reports, and other artifacts.
  - Automatically uploads indicators, samples, and e-mails to CRITs and creates appropriate relationships between them.
  - Maintains an event repository containing copies of the ACE alerts and all their artifacts.
  - Creates a shareable intel package containing a summary of the event including indicators, malware samples, and emails.
  
See https://eventsentry.readthedocs.io/en/latest/ for more information on Event Sentry.

Metrics
-------

ACE's Metrics page can be used to track and display metrics for alert triage operations. Currently, the following tables can be generated:

    :Alert Quantities: Count of alerts by disposition
    :Hours of Operation: Cycle time averages and quantities by the time of day alerts were generated
    :Alert Cycle Times: The average time it took to disposition alerts in business hours
    :Incidents: Summary of incidents (an incident is an event that has progressed beyond DELIVERY)
    :Events: Summary of events
    :CRITS Indicator Stats: Count of indicators by intel source and status


