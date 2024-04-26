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
"""Templates of base java project files"""

DOCKERFILE_JAVA = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L https://dlcdn.apache.org//ant/binaries/apache-ant-1.10.14-bin.zip -o ant.zip && unzip ant.zip -d $SRC/ant && rm -rf ant.zip
RUN curl -L https://services.gradle.org/distributions/gradle-7.4.2-bin.zip -o gradle.zip && unzip gradle.zip -d $SRC/gradle && rm -rf gradle.zip
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.2/binaries/apache-maven-3.9.2-bin.zip -o maven.zip && unzip maven.zip -d $SRC/maven && rm -rf maven.zip
RUN curl -L https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip -o protoc.zip && mkdir -p $SRC/protoc && unzip protoc.zip -d $SRC/protoc && rm -rf protoc.zip
RUN curl -L https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz -o jdk.tar.gz && tar zxf jdk.tar.gz && rm -rf jdk.tar.gz
ENV ANT="$SRC/ant/apache-ant-1.10.14/bin/ant"
ENV GRADLE_HOME="$SRC/gradle/gradle-7.4.2"
ENV GRADLE_OPTS="-Dfile.encoding=utf-8"
ENV MVN="$SRC/maven/apache-maven-3.9.2/bin/mvn"
ENV JAVA_HOME="$SRC/jdk-15.0.2"
ENV PATH="$JAVA_HOME/bin:$SRC/ant/apache-ant-1.10.14/bin:$SRC/gradle/gradle-7.4.2/bin:$SRC/maven/apache-maven-3.9.2/bin:$SRC/protoc/bin:$PATH"
RUN git clone --depth 1 TARGET_REPO proj
COPY *.sh *.java $SRC/
WORKDIR $SRC/proj
"""

DOCKERFILE_JAVA_TEST = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz -o jdk.tar.gz && tar zxf jdk.tar.gz && rm -rf jdk.tar.gz
ENV JAVA_HOME="$SRC/jdk-15.0.2"
COPY built_jar FuzzTest.java build.sh $SRC/
WORKDIR $SRC/
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

find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.5</compilerVersion>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.6</compilerVersion>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/source>1.5</source>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/source>1.6</source>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/target>1.5</target>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/target>1.6</target>1.8</g' {} \;
find ./ -name pom.xml -exec sed -i 's/java15/java18/g' {} \;
find ./ -name pom.xml -exec sed -i 's/java16/java18/g' {} \;
find ./ -name pom.xml -exec sed -i 's/java-1.5/java-1.8/g' {} \;
find ./ -name pom.xml -exec sed -i 's/java-1.6/java-1.8/g' {} \;

mkdir -p ~/.m2
echo "<toolchains><toolchain><type>jdk</type><provides><version>1.8</version></provides>" > ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "<toolchain><type>jdk</type><provides><version>8</version></provides>" >> ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "<toolchain><type>jdk</type><provides><version>11</version></provides>" >> ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "<toolchain><type>jdk</type><provides><version>14</version></provides>" >> ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "<toolchain><type>jdk</type><provides><version>15</version></provides>" >> ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "<toolchain><type>jdk</type><provides><version>17</version></provides>" >> ~/.m2/toolchains.xml
echo "<configuration><jdkHome>\${env.JAVA_HOME}</jdkHome></configuration></toolchain>" >> ~/.m2/toolchains.xml
echo "</toolchains>" >> ~/.m2/toolchains.xml

$MVN clean package -Dmaven.javadoc.skip=true -DskipTests=true -Dpmd.skip=true -Dencoding=UTF-8 \
-Dmaven.antrun.skip=true -Dcheckstyle.skip=true dependency:copy-dependencies
"""

BUILD_JAVA_BASE = r"""
wget -P $OUT/ https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar

cd $BASEDIR

mkdir -p $OUT/built_jar
for JARFILE in $(find ./  -name "*.jar")
do
  if [[ "$JARFILE" != *sources.jar ]] && [[ "$JARFILE" != *javadoc.jar ]] && [[ "$JARFILE" != *tests.jar ]]
  then
    cp $JARFILE $OUT/built_jar
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

BUILD_CLASSPATH=$JAZZER_API_PATH:$OUT/jar_temp:$OUT/commons-lang3-3.12.0.jar
RUNTIME_CLASSPATH=\$this_dir/jar_temp:\$this_dir/commons-lang3-3.12.0.jar:\$this_dir

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

BUILD_JAVA_INTROSPECTOR = """
cd /fuzz-introspector/frontends/java
./run.sh --jarfile $OUT/built_jar/*.jar: --entryclass Fuzz --src $SRC/proj --autofuzz
cp ./fuzzerLogFile-Fuzz.data $OUT/
cp ./fuzzerLogFile-Fuzz.data.yaml $OUT/
"""

BUILD_JAVA_TEST = """
mkdir $SRC/jar_temp
cd $SRC/jar_temp
for JARFILE in `ls $SRC/*.jar`
do
  jar -xf $JARFILE
done
cd $SRC
wget https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
BUILD_CLASSPATH=$JAZZER_API_PATH:$SRC/jar_temp:$SRC/commons-lang3-3.12.0.jar
$JAVA_HOME/bin/javac -cp $BUILD_CLASSPATH FuzzTest.java
"""

YAML_JAVA = """homepage: https://google.com
main_repo: TARGET_REPO
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
