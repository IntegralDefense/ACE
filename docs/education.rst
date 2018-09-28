Some Background
===============

If you're curious about where ACE came from or the bigger picture of how ACE is meant to be used, the following topics cover some concepts at a high level that should first be understood.

Additionally, John Davison gave a talk on the development of the ACE toolset at BSides Cincinnati in 2015 and covers these same topics. You can watch his presentation here:

.. raw:: html

   <iframe width="560" height="315" src="https://www.youtube.com/embed/okMkF-NYCHk?rel=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>

Driving Behavior
----------------

With the goal set at always detecting advanced attacks and attackers across an organization, you must have detection point coverage across your entire attack surface. This can be challenging in a world of constraints, such as your analysts' time. Analysts cannot be inundated with an unmanageable number of alerts; nor should they be presented with the same alert repeatedly. You need to manage and optimize the volume of alerts presented to analysts. The best way to do this is to get a handle on your False Positive metrics and how those metrics should drive your hunting and tuning behavior. 

THE METRIC TO DRIVE: Assume the majority of all alerts are False Positive, then for each alert that is analyzed, how long does it take the analyst to **realize** it is a False Positive? 

Why does this metric matter? Because detection is hard and analyst time is highly valuable to a successful security operation.

False Positive Metrics
++++++++++++++++++++++

What is a False Postive?
Something that turns out to be nothing? Yes, but more than that, too.

False Positives, False Positive rates, and the average time it takes an analyst to disposition a False Positive are crucial metrics for driving the right security ecosystem.

If your least experienced analyst can't disposition a False Positive in seconds, then it’s going to be much harder to both expand and maintain an in-depth coverage of your attack surface. This is, of course, assuming that your security operation is constrained by time, money, and analyst sanity.


Hunting and Tuning!
+++++++++++++++++++

Hunting is the active process of searching for maliciousness. From hunting, we develop hunts that are meant to detect some specific form of maliciousness. A hunt could be looking for a strange process behavioral pattern, a Yara signature, or just a search for some atomic indicators. When a hunt returns a result, we have a detection and need to create an alert.

Hunts produce True Positives and False Positives. Tuning is the process of telling a hunt not to alert on something we've already determined to be a False Positive. Tune out the False Positives.

Not sure when to hunt and tune? If the detection team can handle 'X' number of alerts in a day, and if 'n' is the number of alerts your tools generate in a day:

  - If n >= X then **tune**.
  - If n < X then **hunt** and introduce more alerts for the analysts

  Hunt + Tune == Coverage++

With an understanding of your False Positive metrics, hunting and tuning can be used to expand your attack surface coverage.

