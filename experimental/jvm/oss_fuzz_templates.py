#!/usr/bin/env python3
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
"""Templates of base java project files"""

DOCKERFILE_JAVA_ANT = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L {ANT_URL} -o ant.zip && unzip ant.zip -d $SRC/ant && rm -rf ant.zip
RUN curl -L {PROTO_URL} -o protoc.zip && mkdir -p $SRC/protoc && unzip protoc.zip -d $SRC/protoc && rm -rf protoc.zip
RUN curl -L {JDK15_URL} -o jdk.tar.gz && tar zxf jdk.tar.gz && rm -rf jdk.tar.gz
ENV ANT="$SRC/ant/apache-ant-1.10.14/bin/ant"
ENV JAVA_HOME="$SRC/jdk-15.0.2"
ENV PATH="$JAVA_HOME/bin:$SRC/ant/apache-ant-1.10.14/bin:$SRC/protoc/bin:$PATH"
RUN git clone --depth 1 {TARGET_REPO} proj
COPY *.sh *.java $SRC/
WORKDIR $SRC/proj
"""

DOCKERFILE_JAVA_GRADLE = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L {GRADLE_URL} -o gradle.zip && unzip gradle.zip -d $SRC/gradle && rm -rf gradle.zip
RUN curl -L {PROTO_URL} -o protoc.zip && mkdir -p $SRC/protoc && unzip protoc.zip -d $SRC/protoc && rm -rf protoc.zip
RUN curl -L {JDK15_URL} -o jdk.tar.gz && tar zxf jdk.tar.gz && rm -rf jdk.tar.gz
ENV GRADLE_HOME="$SRC/gradle/gradle-7.4.2"
ENV GRADLE_OPTS="-Dfile.encoding=utf-8"
ENV JAVA_HOME="$SRC/jdk-15.0.2"
ENV PATH="$JAVA_HOME/bin:$SRC/gradle/gradle-7.4.2/bin:$SRC/protoc/bin:$PATH"
RUN git clone --depth 1 {TARGET_REPO} proj
COPY *.sh *.java $SRC/
WORKDIR $SRC/proj
"""

DOCKERFILE_JAVA_MAVEN = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L {MAVEN_URL} -o maven.zip && unzip maven.zip -d $SRC/maven && rm -rf maven.zip
RUN curl -L {PROTO_URL} -o protoc.zip && mkdir -p $SRC/protoc && unzip protoc.zip -d $SRC/protoc && rm -rf protoc.zip
RUN curl -L {JDK15_URL} -o jdk.tar.gz && tar zxf jdk.tar.gz && rm -rf jdk.tar.gz
ENV MVN="$SRC/maven/apache-maven-{MAVEN_VERSION}/bin/mvn"
ENV JAVA_HOME="$SRC/jdk-15.0.2"
ENV PATH="$JAVA_HOME/bin:$SRC/maven/apache-maven-{MAVEN_VERSION}/bin:$SRC/protoc/bin:$PATH"
RUN git clone --depth 1 {TARGET_REPO} proj
COPY *.sh *.java $SRC/
WORKDIR $SRC/proj
"""

BUILD_JAVA_ANT = """BASEDIR=$(pwd)
chmod +x $SRC/protoc/bin/protoc
$ANT
"""

BUILD_JAVA_GRADLE = """BASEDIR=$(pwd)
if test -f "gradlew"
then
  export GRADLE="./gradlew"
fi

chmod +x $SRC/protoc/bin/protoc
rm -rf $HOME/.gradle/caches/
chmod +x $GRADLE

EXCLUDE_SPOTLESS_CHECK=
if $GRADLE tasks --all | grep -qw "^spotlessCheck"
then
  EXCLUDE_SPOTLESS_CHECK="-x spotlessCheck "
fi

$GRADLE --no-daemon clean build -x test -x javadoc -x sources \
$EXCLUDE_SPOTLESS_CHECK\
-Porg.gradle.java.installations.auto-detect=false \
-Porg.gradle.java.installations.auto-download=false \
-Porg.gradle.java.installations.paths=$JAVA_HOME
"""

BUILD_JAVA_MAVEN = r"""BASEDIR=$(pwd)
chmod +x $SRC/protoc/bin/protoc

$MVN clean package -Dmaven.javadoc.skip=true -DskipTests=true -Dpmd.skip=true -Dencoding=UTF-8 \
-Dmaven.antrun.skip=true -Dcheckstyle.skip=true dependency:copy-dependencies
"""

BUILD_JAVA_BASE = r"""
cd $BASEDIR

mkdir -p $OUT/built_jar
for JARFILE in $(find ./  -name "*.jar")
do
  if [[ "$JARFILE" == *"target/"* ]] || [[ "$JARFILE" == *"build/"* ]] || [[ "$JARFILE" == *"dist/"* ]]
  then
    if [[ "$JARFILE" != *sources.jar ]] && [[ "$JARFILE" != *javadoc.jar ]] && [[ "$JARFILE" != *tests.jar ]]
    then
      if [[ "$JARFILE" != *"dependency/"* ]]
      then
        cp $JARFILE $OUT/
      fi
      cp $JARFILE $OUT/built_jar
    fi
  fi
done

curr_dir=$(pwd)
rm -rf $OUT/jar_temp
mkdir $OUT/jar_temp
cd $OUT/jar_temp
for JARFILE in `ls $OUT/built_jar/*.jar`
do
  jar -xf $JARFILE
done

cd $curr_dir
cp -r $JAVA_HOME $OUT/

BUILD_CLASSPATH=$JAZZER_API_PATH:$OUT/jar_temp:
RUNTIME_CLASSPATH=\$this_dir/jar_temp:\$this_dir

for fuzzer in $(ls $SRC/Fuzz*.java)
do
  fuzzer_basename=$(basename -s .java $fuzzer)
  $JAVA_HOME/bin/javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
  jar cvf $OUT/$fuzzer_basename.jar -C $SRC $fuzzer_basename.class
  cp $OUT/$fuzzer_basename.jar $OUT/built_jar/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash

  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname \"\$0\")
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]
  then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi

  export JAVA_HOME=\$this_dir/$(basename $JAVA_HOME)
  export LD_LIBRARY_PATH=\"\$JAVA_HOME/lib/server\":\$this_dir
  export PATH=\$JAVA_HOME/bin:\$PATH

  \$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
  --cp=$RUNTIME_CLASSPATH \
  --target_class=$fuzzer_basename \
  --jvm_args=\"\$mem_settings\" \
  \$@" > $OUT/$fuzzer_basename

  chmod u+x $OUT/$fuzzer_basename
done
"""

YAML_JAVA = """homepage: https://github.com/google/oss-fuzz-gen
main_repo: {TARGET_REPO}
language: jvm
fuzzing_engines:
- libfuzzer
sanitizers:
- address
primary_contacts: oss-fuzz-gen@google.com
"""

FUZZER_JAVA = """import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Fuzz {
  public static void fuzzerInitialize() {
  }

  public static void fuzzerTearDown() {
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
  }
}
"""
