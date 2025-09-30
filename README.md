# LogicFuzz


Current supported models are:
- OpenAI GPT

## Overview of our Agentic design

![overview](./agent_graph/overview.png)


## Detailed workflow of LogicFuzz
![workflow](./agent_graph/workflow.png)



## Basic usage

Currently, we just use version 1: non-agent mode to show the effectiveness.


-----

\* "Total project lines" measures the source code of the project-under-test compiled and linked by the preexisting human-written fuzz targets from OSS-Fuzz.

\* "Total coverage gain" is calculated using a denominator of the "Total project lines". "Total relative gain" is the increase in coverage compared to the old number of covered lines.

\* Additional code from the project-under-test maybe included when compiling the new fuzz targets and result in high percentage gains.
