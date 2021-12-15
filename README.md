![Logpresso Logo](logo.png)

log4j2-scan is a single binary command-line tool for CVE-2021-44228 vulnerability scanning and mitigation patch. It also supports nested JAR file scanning and patch. It also detects CVE-2021-45046 vulnerability (log4j 2.15.0).

### Download
* [log4j2-scan 1.5.0 (Windows x64)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v1.5.0/logpresso-log4j2-scan-1.5.0-win64.7z)
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.
* [log4j2-scan 1.5.0 (Linux x64)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v1.5.0/logpresso-log4j2-scan-1.5.0-linux.tar.gz)
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.
* [log4j2-scan 1.5.0 (Any OS, 10KB)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v1.5.0/logpresso-log4j2-scan-1.5.0.jar)

### How to use
Just run log4j2-scan.exe or log4j2-scan with target directory path.

Usage
```
Logpresso CVE-2021-44228 Vulnerability Scanner 1.5.0 (2021-12-15)
Usage: log4j2-scan [--fix] target_path

--fix
        Backup original file and remove JndiLookup.class from JAR recursively.
--force-fix
        Do not prompt confirmation. Don't use this option unless you know what you are doing.
--debug
        Print exception stacktrace for debugging.
--trace
        Print all directories and files while scanning.
--silent
        Do not print anything until scan is completed.
--scan-zip
        Scan also .zip extension files. This option may slow down scanning.
--no-symlink
        Do not detect symlink as vulnerable file.
--exclude [path_prefix]
        Exclude specified paths. You can specify multiple --exclude [path_prefix] pairs
--exclude-config [file_path]
        Specify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.
--all-drives
        Scan all drives on Windows
--drives c,d
        Scan specified drives on Windows. Spaces are not allowed here.
```

On Windows
```
log4j2-scan [--fix] target_path
```
On Linux
```
./log4j2-scan [--fix] target_path
```
On UNIX (AIX, Solaris, and so on)
```
java -jar logpresso-log4j2-scan-1.5.0.jar [--fix] target_path
```

If you add `--fix` option, this program will copy vulnerable original JAR file to .bak file, and create new JAR file without `org/apache/logging/log4j/core/lookup/JndiLookup.class` entry. In most environments, JNDI lookup feature will not be used. However, you must use this option at your own risk. It is necessary to shutdown any running JVM process before applying patch. Start affected JVM process after fix.

If you want to automate patch job, use `--force-fix` option. With this option, this program will no longer prompt for confirmation.

`(mitigated)` tag will be displayed if `org/apache/logging/log4j/core/lookup/JndiLookup.class` entry is removed from JAR file.

If you add `--trace` option, this program will print all visited directories and files. Use this option only for debugging.

On Windows:
```
CMD> log4j2-scan.exe D:\tmp
[*] Found CVE-2021-44228 vulnerability in D:\tmp\elasticsearch-7.16.0\bin\elasticsearch-sql-cli-7.16.0.jar, log4j 2.11.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\elasticsearch-7.16.0\lib\log4j-core-2.11.1.jar, log4j 2.11.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\flink-1.14.0\lib\log4j-core-2.14.1.jar, log4j 2.14.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\logstash-7.16.0\logstash-core\lib\jars\log4j-core-2.14.0.jar, log4j 2.14.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\logstash-7.16.0\vendor\bundle\jruby\2.5.0\gems\logstash-input-tcp-6.2.1-java\vendor\jar-dependencies\org\logstash\inputs\logstash-input-tcp\6.2.1\logstash-input-tcp-6.2.1.jar, log4j 2.9.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-7.7.3\solr-7.7.3\contrib\prometheus-exporter\lib\log4j-core-2.11.0.jar, log4j 2.11.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-7.7.3\solr-7.7.3\server\lib\ext\log4j-core-2.11.0.jar, log4j 2.11.0
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-8.11.0\contrib\prometheus-exporter\lib\log4j-core-2.14.1.jar, log4j 2.14.1
[*] Found CVE-2021-44228 vulnerability in D:\tmp\solr-8.11.0\server\lib\ext\log4j-core-2.14.1.jar, log4j 2.14.1

Scanned 5047 directories and 26251 files
Found 9 vulnerable files
Completed in 0.42 seconds
```

### How it works
Run in 5 steps:
1. Find all .jar, .war, .ear, .aar files recursively.
2. Find `META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties` entry from JAR file.
3. Read groupId, artifactId, and version.
4. Compare log4j2 version and print vulnerable version.
5. If --fix option is used, backup vulnerable file and patch it.
   * For example, original vulnerable.jar is copied to vulnerable.jar.bak

### Contact
If you have any question or issue, create an issue in this repository.
