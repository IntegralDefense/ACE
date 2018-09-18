Background & Philosophy
=======================

What is a False Positive?
-------------------------

Metrics to Drive Behavior
-------------------------

Alert Triage
------------

Hunting & Tuning
----------------


False Positive Posulate
=======================

What do False Postives mean to a detect guy, an analyst?

  - How are FP metrics used to drive behavior where you're working at?

  - traditional FP Graph always trending up

What is a False Positive?

  - Something that turns out to be nothing..


What is a True Positive?

  - Something that turns out to be Malicious.

What about a gray area paradox?

  - detect someone attempting a wordpress vulnerability against us, however, we're not running wordpress.. so we don't care. hmm


Well, we're either gonna respond or not respond to an alert or not...

  - SO - A False Positive is an Alert the analyst is not going to respond to.



99% of all alerts are False Postive, aka., 99% of all Alerts do not require a response by the analyst.


What does this mean? 

  - 99% of my intel sucks?
  - 99% of my signatures suck?
  - 99% of the time I'm wasting my time?

Does it matter how many FPs there are?

  - Yes! It's the most important thing.

  If you chart all of your alerts, 99% of them are going to be similar to your FP graph.

The 1%::

  - Form of an Alert
  - The Alert needs to be in your list of alerts to review
  - The chance that you'll alert on something depends entirely on **your coverage of the attack surface**
  - Wider coverage leads means more alerts, which means more FPs


detection points!!!


Hunting and Tuning!!!

Hunt -- Signature Development
   - Behaviourly analysis
   - yara signatures
   - Atomic Indicators


The detection team can handle X alerts in a day. And if n = the number of alerts your tools generate in a day. Then,

  - If n >= X then *tune*.
  - If n < X then *hunt*. And introduce more alerts for the analysts

Now, Hunt + Tune == ++Coverage




Now, our graph of False Positive Rates should be mostly steady.


THE METRIC TO DRIVE: If 99% of all alerts are False Positive, then for each alert that is analyzed, how long does it take to *realize* it is a False Positive? 

Why does this metric matter? Because Detection is Hard and Analyst time is highly valuable to a sucessful security operation.




Tune -- Tune out the False Positives

The tool begins
---------------

What if you had a magical tool that somehow, for each alert, gave the analyst enough information that he or she could quickly determine that the alert was a False Positive?
 How would that affect things?

  - Super fast dispositioning

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
