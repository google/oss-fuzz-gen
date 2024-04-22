# Java auto-gen

Logic for auto-generating java fuzzers.

Sample:

```sh
python3 -m java_fuzzgen.build -r https://github.com/jboss-javassist/javassist,https://github.com/stleary/JSON-java -l mylog1.txt -m 50
```

or 

```sh
python3 -m java_fuzzgen.build -rf project_list -l mylog1.txt -m 50
```
where all the project urls are stored in the text file project_list on each line.
