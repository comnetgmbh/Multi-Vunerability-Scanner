package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.logpresso.scanner.utils.IoUtils;

public class Configuration {
	private static final boolean isWindows = File.separatorChar == '\\';

	private List<String> targetPaths = new LinkedList<String>();
	private boolean debug = false;
	private boolean trace = false;
	private boolean silent = false;
	private boolean fix = false;
	private boolean force = false;
	private boolean scanZip = false;
	private boolean noSymlink = false;
	private boolean allDrives = false;
	private boolean reportCsv = false;
	private boolean reportJson = false;
	private boolean scanForLog4j1 = false;
	private boolean scanForLogback = false;
	private boolean noEmptyReport = false;
	private boolean oldExitCode = false;
	private Charset zipCharset = null;

	private String reportPath = null;
	private String reportDir = null;
	private String includeFilePath = null;
	private Set<File> driveLetters = new TreeSet<File>();
	private List<String> excludePaths = new ArrayList<String>();
	private List<String> excludePatterns = new ArrayList<String>();
	private Set<String> excludeFileSystems = new HashSet<String>();

	public static void pringUsage() {
		System.out.println("Usage: log4j2-scan [--scan-log4j1] [--fix] target_path1 target_path2");
		System.out.println("");
		System.out.println("-f [config_file_path]");
		System.out.println("\tSpecify config file path which contains scan target paths.\n"
				+ "\tPaths should be separated by new line. Prepend # for comment.");
		System.out.println("--scan-log4j1");
		System.out.println("\tEnables scanning for log4j 1 versions.");
		System.out.println("--scan-logback");
		System.out.println("\tEnables scanning for logback CVE-2021-42550.");
		System.out.println("--scan-zip");
		System.out.println("\tScan also .zip extension files. This option may slow down scanning.");
		System.out.println("--zip-charset");
		System.out.println(
				"\tSpecify an alternate zip encoding other than utf-8. System default charset is used if not specified.");
		System.out.println("--fix");
		System.out.println("\tBackup original file and remove JndiLookup.class from JAR recursively.");
		System.out.println(
				"\tWith --scan-log4j1 option, it also removes JMSAppender.class, SocketServer.class, SMTPAppender.class, SMTPAppender$1.class");
		System.out.println("--force-fix");
		System.out.println("\tDo not prompt confirmation. Don't use this option unless you know what you are doing.");
		System.out.println("--all-drives");
		System.out.println("\tScan all drives on Windows");
		System.out.println("--drives c,d");
		System.out.println("\tScan specified drives on Windows. Spaces are not allowed here.");
		System.out.println("--no-symlink");
		System.out.println("\tDo not detect symlink as vulnerable file.");
		System.out.println("--exclude [path_prefix]");
		System.out.println("\tExclude specified paths. You can specify multiple --exclude [path_prefix] pairs");
		System.out.println("--exclude-config [config_file_path]");
		System.out.println(
				"\tSpecify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.");
		System.out.println("--exclude-pattern [pattern]");
		System.out.println(
				"\tExclude specified paths by pattern. You can specify multiple --exclude-pattern [pattern] pairs (non regex)");
		System.out.println("--exclude-fs nfs,tmpfs");
		System.out.println("\tExclude paths by file system type. nfs, tmpfs, devtmpfs, and iso9660 is ignored by default.");
		System.out.println("--report-csv");
		System.out.println(
				"\tGenerate log4j2_scan_report_yyyyMMdd_HHmmss.csv in working directory if not specified otherwise via --report-path [path]");
		System.out.println("--report-json");
		System.out.println(
				"\tGenerate log4j2_scan_report_yyyyMMdd_HHmmss.json in working directory if not specified otherwise via --report-path [path]");
		System.out.println("--report-path");
		System.out.println("\tSpecify report output path including filename. Implies --report-csv.");
		System.out.println("--report-dir");
		System.out.println("\tSpecify report output directory. Implies --report-csv.");
		System.out.println("--no-empty-report");
		System.out.println("\tDo not generate empty report.");
		System.out.println("--old-exit-code");
		System.out.println("\tReturn sum of vulnerable and potentially vulnerable files as exit code.");
		System.out.println("--debug");
		System.out.println("\tPrint exception stacktrace for debugging.");
		System.out.println("--trace");
		System.out.println("\tPrint all directories and files while scanning.");
		System.out.println("--silent");
		System.out.println("\tDo not print anything until scan is completed.");
		System.out.println("--help");
		System.out.println("\tPrint this help.");
	}

	public static Configuration parseArguments(String[] args) throws Exception {
		Configuration c = new Configuration();

		int i = 0;
		for (; i < args.length; i++) {
			if (args[i].equals("--fix")) {
				c.fix = true;
			} else if (args[i].equals("--force-fix")) {
				c.fix = true;
				c.force = true;
			} else if (args[i].equals("--debug")) {
				c.debug = true;
			} else if (args[i].equals("--trace")) {
				c.trace = true;
			} else if (args[i].equals("--silent")) {
				c.silent = true;
			} else if (args[i].equals("--scan-zip")) {
				c.scanZip = true;
			} else if (args[i].equals("--zip-charset")) {
				verifyArgument(args, i, "ZIP Charset", "Specify zip entry encoding.");
				c.zipCharset = Charset.forName(args[i + 1]);
				i++;
			} else if (args[i].equals("--no-symlink")) {
				c.noSymlink = true;
			} else if (args[i].equals("--scan-log4j1")) {
				c.scanForLog4j1 = true;
			} else if (args[i].equals("--scan-logback")) {
				c.scanForLogback = true;
			} else if (args[i].equals("--help") || args[i].equals("-h")) {
				pringUsage();
				System.exit(-1);
			} else if (args[i].equals("-f")) {
				verifyArgument(args, i, "Input config file", "Specify input config file path.");
				c.includeFilePath = args[i + 1];

				File f = new File(c.includeFilePath);
				if (!f.exists())
					throw new IllegalArgumentException("Cannot read include config file: " + f.getAbsolutePath());

				i++;
			} else if (args[i].equals("--all-drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--all-drives is supported on Windows only.");

				c.allDrives = true;
			} else if (args[i].equals("--drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--drives is supported on Windows only.");

				verifyArgument(args, i, "Drive letter", "Specify drive letters.");

				for (String letter : args[i + 1].split(",")) {
					letter = letter.trim().toUpperCase();
					if (letter.length() == 0)
						continue;

					verifyDriveLetter(letter);
					c.driveLetters.add(new File(letter + ":\\"));
				}

				i++;
			} else if (args[i].equals("--exclude")) {
				verifyArgument(args, i, "Exclude path", "Specify exclude file path.");

				String path = args[i + 1];
				if (isWindows)
					path = path.toUpperCase();

				c.excludePaths.add(path);
				i++;
			} else if (args[i].equals("--exclude-pattern")) {
				verifyArgument(args, i, "Pattern", "Specify exclude pattern.");

				String pattern = args[i + 1];
				if (isWindows)
					pattern = pattern.toUpperCase();

				c.excludePatterns.add(pattern);
				i++;
			} else if (args[i].equals("--exclude-config")) {
				verifyArgument(args, i, "Exclude config file path", "Specify exclude file path.");

				File f = new File(args[i + 1]);
				if (!f.exists() || !f.canRead())
					throw new IllegalArgumentException("Cannot read exclude config file: " + f.getAbsolutePath());

				c.loadExcludePaths(f);
				i++;
			} else if (args[i].equals("--exclude-fs")) {
				verifyArgument(args, i, "File system type", "Specify file system types.");

				for (String type : args[i + 1].split(",")) {
					type = type.trim().toLowerCase();
					if (type.length() == 0)
						continue;

					c.excludeFileSystems.add(type);
				}

				i++;

			} else if (args[i].equals("--report-csv")) {
				c.reportCsv = true;
			} else if(args[i].equals("--report-json")) {
				c.reportJson = true;
			} else if (args[i].equals("--report-path")) {
				verifyArgument(args, i, "Report path", "Specify report output path.");

				c.reportCsv = true;
				c.reportPath = args[i + 1];

				File reportFile = new File(c.reportPath);
				if (reportFile.exists())
					throw new IllegalArgumentException("File already exists - " + reportFile.getAbsolutePath());

				i++;
			} else if (args[i].equals("--report-dir")) {
				c.reportCsv = true;

				if (args.length > i + 1) {
					String pattern = args[i + 1];
					if (pattern.startsWith("--"))
						throw new IllegalArgumentException("Report dir should not starts with `--`.");

					c.reportDir = args[i + 1];

					File reportFile = new File(c.reportDir);
					if (!reportFile.exists())
						throw new IllegalArgumentException("Directory not existent - " + reportFile.getAbsolutePath());
					else if (!reportFile.isDirectory())
						throw new IllegalArgumentException("Not a directory - " + reportFile.getAbsolutePath());

					i++;
				} else {
					throw new IllegalArgumentException("Specify report output path.");
				}
			} else if (args[i].equals("--no-empty-report")) {
				c.noEmptyReport = true;
			} else if (args[i].equals("--old-exit-code")) {
				c.oldExitCode = true;
			} else {
				String targetPath = c.fixPathTypo(args[i]);
				File dir = new File(targetPath);
				if (!dir.exists())
					throw new IllegalArgumentException("path not found: " + dir.getAbsolutePath());

				if (!dir.canRead())
					throw new IllegalArgumentException("no permission for " + dir.getAbsolutePath());

				c.targetPaths.add(targetPath);
			}
		}

		// verify drive letters
		c.verifyDriveLetters();

		// apply file system exclusion
		try {

			if (c.excludeFileSystems.isEmpty()) {
				for (String path : PartitionLoader.getExcludePaths(null))
					c.excludePaths.add(path);
			} else {
				for (String path : PartitionLoader.getExcludePaths(c.excludeFileSystems))
					c.excludePaths.add(path);
			}
		} catch (Exception e) {
			if (c.debug)
				e.printStackTrace();
		}

		// verify conflict option
		if (c.allDrives && !c.driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --all-drives and --drives options.");

		if (!c.allDrives && c.driveLetters.isEmpty() && c.includeFilePath == null && c.targetPaths.isEmpty())
			throw new IllegalArgumentException("Specify scan target path.");

		if (c.includeFilePath != null && c.allDrives)
			throw new IllegalArgumentException("Cannot specify both --all-drives and -f options.");

		if (c.includeFilePath != null && !c.driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --drives and -f options.");

		return c;
	}

	private static void verifyDriveLetter(String letter) {
		if (letter.length() > 1)
			throw new IllegalArgumentException("Invalid drive letter: " + letter);

		char c = letter.charAt(0);
		if (c < 'A' || c > 'Z')
			throw new IllegalArgumentException("Invalid drive letter: " + letter);
	}

	private static void verifyArgument(String[] args, int i, String name, String error) {
		if (args.length == i + 1)
			throw new IllegalArgumentException(error);

		if (args[i + 1].startsWith("--"))
			throw new IllegalArgumentException(name + " should not starts with `--`.");
	}

	private String fixPathTypo(String s) {
		// auto completion for C:
		if (s.length() == 2 && s.charAt(1) == ':') {
			char letter = s.toUpperCase().charAt(0);
			if (letter >= 'A' && letter <= 'Z')
				return s + "\\";
		}
		return s;
	}

	private void loadExcludePaths(File f) throws IOException {
		FileInputStream fis = null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "utf-8"));

			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();

				if (line.startsWith("#") || line.isEmpty())
					continue;

				if (isWindows)
					line = line.toUpperCase();

				excludePaths.add(line);
			}

		} finally {
			IoUtils.ensureClose(fis);
			IoUtils.ensureClose(br);
		}
	}

	private void verifyDriveLetters() {
		File[] roots = File.listRoots();
		Set<File> availableRoots = new HashSet<File>();
		if (roots != null) {
			for (File root : roots) {
				availableRoots.add(root);
			}
		}

		for (File letter : driveLetters) {
			if (!availableRoots.contains(letter))
				throw new IllegalStateException("Unknown drive: " + letter);
		}
	}

	public List<String> getTargetPaths() {
		return targetPaths;
	}

	public boolean isDebug() {
		return debug;
	}

	public boolean isTrace() {
		return trace;
	}

	public boolean isSilent() {
		return silent;
	}

	public boolean isFix() {
		return fix;
	}

	public boolean isForce() {
		return force;
	}

	public boolean isScanZip() {
		return scanZip;
	}

	public Charset getZipCharset() {
		return zipCharset;
	}

	public boolean isNoSymlink() {
		return noSymlink;
	}

	public boolean isAllDrives() {
		return allDrives;
	}

	public boolean isReportCsv() {
		return reportCsv;
	}

	public boolean isReportJson() {
		return reportJson;
	}

	public boolean isScanForLog4j1() {
		return scanForLog4j1;
	}

	public boolean isScanForLogback() {
		return scanForLogback;
	}

	public boolean isNoEmptyReport() {
		return noEmptyReport;
	}

	public boolean isOldExitCode() {
		return oldExitCode;
	}

	public String getReportPath() {
		return reportPath;
	}

	public String getReportDir() {
		return reportDir;
	}

	public String getIncludeFilePath() {
		return includeFilePath;
	}

	public Set<File> getDriveLetters() {
		return driveLetters;
	}

	public List<String> getExcludePaths() {
		return excludePaths;
	}

	public List<String> getExcludePatterns() {
		return excludePatterns;
	}

	public Set<String> getExcludeFileSystems() {
		return excludeFileSystems;
	}
}
