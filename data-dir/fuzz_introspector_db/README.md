# DB creator

This logic creates a database in the form of .json files that is digestible
by the webapp.

The raw data that is being used is the Fuzz Introspector reports created
daily by OSS-Fuzz. These are available at URLs such as [this](https://storage.googleapis.com/oss-fuzz-introspector/htslib/inspector-report/20240306/fuzz_report.html).
These reports, for all OSS-Fuzz projects, are digested and narrowed down into
smaller units of data, which are then merged into data structures that
represent the macro-state of OSS-Fuzz. For example, in order to count lines
covered by OSS-Fuzz in total we merge data from all OSS-Fuzz projects.

The DB is created by `web_db_creator_from_summary.py`. The `summary` in this
filename is a reference to the `summary.json` files that Fuzz Introspector
outputs for each report, such as [this for the above report](https://storage.googleapis.com/oss-fuzz-introspector/htslib/inspector-report/20240306/summary.json).
However, the DB now digests additional files from the Fuzz Introspector
reports and not only the `summary.json` files, although they play a large part.

To generate the DB you can use two scripts:

- `launch_minor_oss_fuzz.sh`: this script generates a DB based on just a few
  OSS-Fuzz projects. It will select minimum 10 projects to include in the DB.
  To control the specific projects to include in the DB you can add/remove
  project names from `must_include_small.config`. This script will take a few
  minutes to complete.
- `launch_full_oss_fuzz.sh`: this script will generate a full historical
  database of all OSS-Fuzz projects. This can take several hours (maximum 6-7)
  to complete.
