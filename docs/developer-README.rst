================
Developer README
================
This document explains the reasons behind some of the stranger design decisions made for this project.

----------
SAQ = ACE
----------
When the project first started we called it the Simple Alert Queue (SAQ). It was later renamed to the Analysis Correlation Engine (ACE). There are still a lot of references to SAQ left, including the name of the core library (``import saq``) and the SAQ_HOME environment variable.

--------------------------------------------
Eveything was initially command line driven.
--------------------------------------------
The original UI of the project was CLI. So there's still a lot of that left. Most of what you can do can also be done via the command line, including full analysis of observables.

Along those lines, it was also meant to be able to be executed from any directory. This is probably no longer true, but there are a number of times where the code assumes it is running in some other directory.

-----------------------------
This was an internal project.
-----------------------------
There's a number of basic things that you would expect would exist that don't. For example, there's no way to manage users from the GUI. It must be done from the command line. And even then, there's no support to delete a user. We didn't have any turnover for 5 years so this was never a requirement.

And the along those lines there's little effort put into account security internally. There are no "roles" or "administrators".

------------------------
The database came later.
------------------------
Very little of the analysis data is stored in the database.

From the beginning of the project I wanted the data to be stored in a schema-less JSON structure on the filesystem. This would allow analysts to simply grep the files for whatever they were looking for. I (reluctantly) looked at MongoDB as a way to index the data and speed up the searches. This was quickly abandoned (it was slowing down development for various reasons.) Later when the GUI was added to the project we started storing data in MySQL.

I knew that we would be modifying this system a lot. So trying to create a database schema that encompassed everything we would ever want to do was not realisitic. Making major changes to large database schemas is no easy task.

Today the database is used to manage the workload of the collectors and engines, and to provide the GUI (and API) for the analysts. The ``data.json`` JSON files that hold the results of the analysis are actually the official records of the analysis. The database is kept in sync with these files.

At some point it would make sense to index these JSON files in a system like Elasticsearch.

-------------
Unit testing.
-------------
My one regret with this project was not creating unit tests as I went. I didn't start adding unit tests until we were ~4 years into the project. Unit test coverage is not what it shoud be, but I would expect that to improve over time.

------------
Final words.
------------
I think it's worth noting that this project was created to enable and improve our analysts. We were not designing a *product*. We were also moving as quickly as we saw threat actors change tactics. As soon as we saw a new techique being used, we would quickly implement a feature to ACE that would allow us to detect that. So there's a number of places where the code looks hastily thrown together.

Hopefully this file helps to explain some of the oddness you may see in the code.
