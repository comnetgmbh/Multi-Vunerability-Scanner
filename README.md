![Logpresso Logo](logo.png)

log4j2-scan is a single binary command-line tool for CVE-2021-44228 vulnerability scanning and mitigation patch. It also supports nested JAR file scanning and patch. It also detects CVE-2021-45046 (log4j 2.15.0), CVE-2021-45105 (log4j 2.16.0), CVE-2021-4104 (log4j 1.x), and CVE-2021-42550 (logback 0.9-1.2.7) vulnerabilities.

### Download
* [log4j2-scan 2.2.1 (Windows x64, 7z)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v2.2.1/logpresso-log4j2-scan-2.2.1-win64.7z)
* [log4j2-scan 2.2.1 (Windows x64, zip)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v2.2.1/logpresso-log4j2-scan-2.2.1-win64.zip)
  * If you get `VCRUNTIME140.dll not found` error, install [Visual C++ Redistributable](https://docs.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170).
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.  
  * 7zip is available from www.7zip.org, and is open source and free.
* [log4j2-scan 2.2.1 (Linux x64)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v2.2.1/logpresso-log4j2-scan-2.2.1-linux.tar.gz)
  * If native executable doesn't work, use the JAR instead. 32bit is not supported.
* [log4j2-scan 2.2.1 (Any OS, 20KB)](https://github.com/logpresso/CVE-2021-44228-Scanner/releases/download/v2.2.1/logpresso-log4j2-scan-2.2.1.jar)

### Build
* [How to build Native Image](https://github.com/logpresso/CVE-2021-44228-Scanner/wiki/FAQ#how-to-build-native-image)

### How to use
Just run log4j2-scan.exe or log4j2-scan with target directory path. The logpresso-log4j2-scan.jar should work with JRE/JDK 7+

Usage
```
Logpresso CVE-2021-44228 Vulnerability Scanner 2.2.1 (2021-12-18)
Usage: log4j2-scan [--fix] target_path1 target_path2

-f [file_path]
        Specify target file paths. Paths should be separated by new line. Prepend # for comment.
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
--scan-log4j1
        Enables scanning for log4j 1 versions.
--scan-logback
        Enables scanning for logback CVE-2021-42550.
--scan-zip
        Scan also .zip extension files. This option may slow down scanning.
--no-symlink
        Do not detect symlink as vulnerable file.
--exclude [path_prefix]
        Exclude specified paths. You can specify multiple --exclude [path_prefix] pairs
--exclude-config [file_path]
        Specify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.
--exclude-pattern [pattern]
        Exclude specified paths by pattern. You can specify multiple --exclude-pattern [pattern] pairs (non regex)
--exclude-fs nfs,tmpfs
        Exclude paths by file system type. nfs, tmpfs, devtmpfs, and iso9660 is ignored by default.
--all-drives
        Scan all drives on Windows
--drives c,d
        Scan specified drives on Windows. Spaces are not allowed here.
--report-csv
        Generate log4j2_scan_report_yyyyMMdd_HHmmss.csv in working directory if not specified otherwise via --report-path [path]
--report-path
        Specify report output path including filename. Implies --report-csv.
--report-dir
        Specify report output directory. Implies --report-csv.
--no-empty-report
        Do not generate empty report.
--old-exit-code
        Return sum of vulnerable and potentially vulnerable files as exit code.
--help
        Print this help.
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
java -jar logpresso-log4j2-scan-2.2.1.jar [--fix] target_path
```

If you add `--fix` option, this program will copy vulnerable original JAR file to .bak file, and create new JAR file without `org/apache/logging/log4j/core/lookup/JndiLookup.class` entry. In most environments, JNDI lookup feature will not be used. However, you must use this option at your own risk. Depending the Operating System:

- Windows: It is necessary to shutdown any running JVM process before applying patch due to lock files. Start affected JVM process after fix.
- Linux/macOS: Apply patch, restart the JVM after

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

### Exit code for automation
* -1 failed to run
* 0 for clean (No vulnerability)
* 1 for found
* 2 for some errors

### Contact
If you have any question or issue, create an issue in this repository.
