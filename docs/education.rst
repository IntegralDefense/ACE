Background & Philosophy
=======================

Driving Behavior
----------------

With the goal set at always detecting advanced attacks and attackers across an organization, you must have detection point coverage across your entire attack surface. This can be challenging in a world of constraints, such as Analyst time. Analysts cannot be inundated with an un-manageable number of alerts; nor should they be presented with the same alert repeatedly. You need to manage and optimize the volume of alerts presented to analysts. The best way to do this is to get a handle on your False Positive metrics and how those metrics should drive your Hunting and Tuning behavior. 
THE METRIC TO DRIVE: Assume the majority of all alerts are False Positive, then for each alert that is analyzed, how long does it take the analyst to **realize** it is a False Positive? 
Why does this metric matter? Because Detection is Hard and Analyst time is highly valuable to a successful security operation.

False Positive Metrics
++++++++++++++++++++++

Something that turns out to be nothing? Yes, but more than that, too.

As metrics, False Positives, False Positive Rates, and the average time it takes an analyst to disposition a False Positive, are a (perhaps the) crucial metrics for driving the right security ecosystem. 
If your worst analyst can't disposition a False Positive in seconds, then it’s going to be much harder to both expand and maintain an in-depth coverage of your attack surface. This is, of course, assuming that your security operation is constrained by time, money, and analyst sanity.


Hunting and Tuning!
+++++++++++++++++++

Hunting is the active process of searching for maliciousness. From hunting, we deleop hunts that are meant to detect some specific form of maliciousness. A hunt could be looking for a strange process behavioural patterns, it could be a yara signature, or just a search for some atomic indicators. When a hunt returns a result, we have a detection and we need to Alert.

Hunst produce True Positives and False Positives. Tunning is the process of telling a hunt not to alert on something we've already determined to be a False Positive. Tune out the False Positives.

But when to Hunt and Tune? If the detection team can handle X amount of alerts in a day, and if n = the number of alerts your tools generate in a day. Then,

  - If n >= X then **tune**.
  - If n < X then **hunt**. And introduce more alerts for the analysts

Now, this hunting and tuning will increase our attack surface coverage.:

  Hunt + Tune == Coverage++



Tachtical
~~~~~~~~~


Alert Triage
++++++++++++


- Analysis of the initial alert.
- Observables of identifiable _things_.
- Research of these _things_. Build the case.
- Possibly more observations of identifiable things from the output of the research, leading to more research.
- Possible rabbit holes. Time disapears.
- You begin to develop impressions of what you see, what you observe, and the relationships between those observations.

::

  from humans import emotions


Analysis Correlation Engine




Tagging
+++++++



Display - GUI
+++++++++++++

The GUI must draw the picture or an alert.
The GUI must invoke the correct emotion in the human.

Alert observable tree structure.
