Additional Features
===================

The following are additional ACE features that are not necessary to understand when orienting the analyst with ACE, or didn't quite fit in other areas of the documentation. If you're here, it's assumed that you're familiar with the content in the :ref:`Getting Data into ACE <get-data-in>` and :ref:`Analyst Orientation <analyst-orientation>` sections.

Events
------

ACE's Events page provides an interface for managing response activities. ACE uses Event Sentry, which, automatically manages ACE events and incidents and seeks to automate most of the common tasks performed by an intel analyst.

Some of the major features of Event Sentry:

  - Generates comprehensive wiki write-ups to give analysts deep insight into the event.
  - Detects types of malware using built-in and extendable detection modules.
  - Detects kill chain phase by determining if a user clicked a link, submitted credentials, opened a malware sample, etc.
  - Extracts indicators from e-mails, sandbox reports, and other artifacts.
  - Automatically uploads indicators, samples, and e-mails to CRITs and creates appropriate relationships between them.
  - Maintains an event repository containing copies of the ACE alerts and all their artifacts.
  - Creates a shareable intel package containing a summary of the event including indicators, malware samples, and e-mail headers.

See https://eventsentry.readthedocs.io/en/latest/ for more information on Event Sentry.

Metrics
-------

ACE's Metrics page can be used to track and display metrics for alert triage operations. Currently, the following tables can be generated:

    :Alert Quantities: Count of alerts by disposition
    :Hours of Operation: Cycle time averages and quantities by the time of day alerts were generated
    :Alert Cycle Times: The average time it took to disposition alerts, in Business hours
    :Incidents: Summary of incidents
    :Events: Summary of events
    :CRITS Indicator Stats: Count of indicators by intel source, and count by status


