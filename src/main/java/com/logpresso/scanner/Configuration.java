package com.logpresso.scanner;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.ZipUtils;

public class Configuration {
	private static final boolean isWindows = File.separatorChar == '\\';
	private static final int SYSLOG_FACILITY_KERNEL = 0;
	private static final int SYSLOG_FACILITY_LOCAL7 = 23;

	private String[] args;
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
	private boolean reportPatch = false;
	private boolean scanForLog4j1 = false;
	private boolean scanForCommonsText = false;
	private boolean scanForLogback = false;
	private boolean noEmptyReport = false;
	private boolean oldExitCode = false;
	private Charset zipCharset = null;

	private String apiKey = null;
	private File restorePath = null;
	private File backupPath = null;
	private String backupExt = "zip";
	private String reportPath = null;
	private String reportDir = null;
	private InetSocketAddress udpSyslogAddr = null;
	private boolean rfc5424 = false;
	private SyslogLevel syslogLevel = SyslogLevel.INFO;

	// default syslog facility is LOCAL0
	private int syslogFacility = 16;
	private InetSocketAddress httpProxyAddr;

	private int throttle = 0;
	private String includeFilePath = null;
	private Set<File> driveLetters = new TreeSet<File>();
	private List<String> excludePathPrefixes = new ArrayList<String>();
	private List<String> excludePatterns = new ArrayList<String>();
	private Set<String> excludeFilePaths = new HashSet<String>();
	private Set<String> excludeFileSystems = new HashSet<String>();

	private File csvLogPath = null;
	private File jsonLogPath = null;

	public static void pringUsage() {
		System.out.println("Usage: multi-scan [--scan-commonstext] [--fix] target_path1 target_path2");
		System.out.println("");
		System.out.println("-f [config_file_path]");
		System.out.println("\tSpecify config file path which contains scan target paths.\n"
				+ "\tPaths should be separated by new line. Prepend # for comment.");
		System.out.println("--scan-commonstext");
		System.out.println("\tEnables scanning for commons-txt versions only.");
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
				"\tWith --scan-log4j1 option, it also removes JMSAppender.class, SocketServer.class, SMTPAppender.class, SMTPAppender$1.class,\n"
						+ "\tJMSSink.class, JDBCAppender.class, and all classes of org.apache.log4j.chainsaw package\t");
		System.out.println("--force-fix");
		System.out.println("\tDo not prompt confirmation. Don't use this option unless you know what you are doing.");
		System.out.println("--restore [backup_file_path]");
		System.out.println("\tUnfix JAR files using zip archived file.");
		System.out.println("--backup-path [zip_output_path]");
		System.out.println("\tSpecify backup file path.");
		System.out.println("--backup-ext [zip]");
		System.out.println("\tSpecify backup file extension. zip by default.");
		System.out.println("\tIf --backup-path is specified, this option is ignored.");
		System.out.println("--all-drives");
		System.out.println("\tScan all drives on Windows");
		System.out.println("--drives c,d");
		System.out.println("\tScan specified drives on Windows. Spaces are not allowed here.");
		System.out.println("--no-symlink");
		System.out.println("\tDo not detect symlink as vulnerable file.");
		System.out.println("--exclude [path_prefix]");
		System.out
				.println("\tPath prefixes of directories whose absolute path starts with the specified value will be excluded.\n"
						+ "\tDoes not support relative paths. You can specify multiple --exclude [path_prefix] pairs");
		System.out.println("--exclude-config [config_file_path]");
		System.out.println(
				"\tSpecify exclude path prefix list in text file. Paths should be separated by new line. Prepend # for comment.");
		System.out.println("--exclude-pattern [pattern]");
		System.out.println("\tExclude specified paths of directories by pattern. Supports fragments.\n"
				+ "\tYou can specify multiple --exclude-pattern [pattern] pairs (non regex)");
		System.out.println("--exclude-file-config [config_file_path]");
		System.out.println(
				"\tSpecify exclude file path list in text file. Paths should be separated by new line. Prepend # for comment.");
		System.out.println("--exclude-fs nfs,tmpfs");
		System.out.println("\tExclude paths by file system type. nfs, nfs3, nfs4, afs, cifs, autofs,\n"
				+ "\ttmpfs, devtmpfs, fuse.sshfs, smbfs and iso9660 is ignored by default.");
		System.out.println("--api-key [key]");
		System.out.println("\tSend reports to Logpresso Watch service.");
		System.out.println("--http-proxy [addr:port]");
		System.out.println("\tSend reports via specified HTTP proxy server.");
		System.out.println("--syslog-udp [host:port]");
		System.out.println("\tSend reports to remote syslog host.\n"
				+ "\tSend vulnerable, potentially vulnerable, and mitigated reports by default.");
		System.out.println("--syslog-level [level]");
		System.out.println("\tSend reports only if report is higher or equal to specified level.");
		System.out.println("\tSpecify alert for vulnerable and potentially vulnerable reports.");
		System.out.println("\tSpecify info for vulnerable, potentially vulnerable, and mitigated reports.");
		System.out.println("\tSpecify debug for vulnerable, potentially vulnerable, mitigated, and error reports.");
		System.out.println("--syslog-facility [code]");
		System.out.println("\tDefault value is 16 (LOCAL0). Facility value must be in the range of 0 to 23 inclusive.");
		System.out.println("--rfc5424");
		System.out.println("\tFollow RFC5424 The Syslog Protocol strictly.");
		System.out.println("--report-csv");
		System.out.println(
				"\tGenerate log4j2_scan_report_yyyyMMdd_HHmmss.csv in working directory if not specified otherwise via --report-path [path]");
		System.out.println("--report-json");
		System.out.println(
				"\tGenerate log4j2_scan_report_yyyyMMdd_HHmmss.json in working directory if not specified otherwise via --report-path [path]");
		System.out.println("--report-patch");
		System.out.println("\tReport also patched log4j file.");
		System.out.println("--report-path");
		System.out.println("\tSpecify report output path including filename. Implies --report-csv.");
		System.out.println("--report-dir");
		System.out.println("\tSpecify report output directory. Implies --report-csv.");
		System.out.println("--no-empty-report");
		System.out.println("\tDo not generate empty report.");
		System.out.println("--csv-log-path");
		System.out.println("\tSpecify csv log file path. If log file exists, log will be appended.");
		System.out.println("--json-log-path");
		System.out.println("\tSpecify json log file path. If log file exists, log will be appended.");
		System.out.println("--old-exit-code");
		System.out.println("\tReturn sum of vulnerable and potentially vulnerable files as exit code.");
		System.out.println("--debug");
		System.out.println("\tPrint exception stacktrace for debugging.");
		System.out.println("--trace");
		System.out.println("\tPrint all directories and files while scanning.");
		System.out.println("--silent");
		System.out.println("\tDo not print progress message.");
		System.out.println("--throttle");
		System.out.println("\tLimit scan files per second.");
		System.out.println("--help");
		System.out.println("\tPrint this help.");
	}

	public static Configuration parseArguments(String[] args) throws Exception {
		Configuration c = new Configuration(args);

		int i = 0;
		for (; i < args.length; i++) {
			if (args[i].equals("--fix")) {
				c.fix = true;
			} else if (args[i].equals("--force-fix")) {
				c.fix = true;
				c.force = true;
			} else if (args[i].equals("--restore")) {
				verifyArgument(args, i, "Backup file path", "Specify backup file path.");
				c.restorePath = new File(args[i + 1]);
				if (!c.restorePath.exists())
					throw new IllegalArgumentException("Backup file not found - " + c.restorePath.getAbsolutePath());

				if (!c.restorePath.canRead())
					throw new IllegalArgumentException(
							"Cannot read backup file (no permission): " + c.restorePath.getAbsolutePath());

				if (!ZipUtils.isZipFile(c.restorePath))
					throw new IllegalArgumentException("Backup file should be zip format - " + c.restorePath.getAbsolutePath());

				i++;
			} else if (args[i].equals("--backup-path")) {
				verifyArgument(args, i, "Backup path", "Specify backup file path.");
				c.backupPath = new File(args[i + 1]);
				if (c.backupPath.exists())
					throw new IllegalArgumentException("Backup file already exists - " + c.backupPath.getAbsolutePath());

				i++;
			} else if (args[i].equals("--backup-ext")) {
				verifyArgument(args, i, "Backup extension", "Specify backup extension.");
				c.backupExt = args[i + 1];
				i++;
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
			} else if (args[i].equals("--scan-commonstext")) {
				c.scanForCommonsText = true;
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
					throw new IllegalArgumentException("Cannot read include config file - " + f.getAbsolutePath());

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
				verifyArgument(args, i, "Exclude path", "Specify exclude prefix of directory path.");

				String path = args[i + 1];
				if (isWindows)
					path = path.toUpperCase();

				c.excludePathPrefixes.add(path);
				i++;
			} else if (args[i].equals("--exclude-pattern")) {
				verifyArgument(args, i, "Pattern", "Specify exclude pattern.");

				String pattern = args[i + 1];
				if (isWindows)
					pattern = pattern.toUpperCase();

				c.excludePatterns.add(pattern);
				i++;
			} else if (args[i].equals("--exclude-config")) {
				verifyArgument(args, i, "Exclude config file path", "Specify exclude config path.");

				File f = new File(args[i + 1]);
				if (!f.exists() || !f.canRead() || !f.isFile())
					throw new IllegalArgumentException("Cannot read exclude config file - " + f.getAbsolutePath());

				c.loadExcludePathPrefixes(f);
				i++;
			} else if (args[i].equals("--exclude-file-config")) {
				verifyArgument(args, i, "Exclude file config file path", "Specify exclude file config path.");

				File f = new File(args[i + 1]);
				if (!f.exists() || !f.canRead() || !f.isFile())
					throw new IllegalArgumentException("Cannot read exclude file config - " + f.getAbsolutePath());

				c.loadExcludeFilePaths(f);
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

			} else if (args[i].equals("--syslog-udp")) {
				verifyArgument(args, i, "Syslog host address",
						"Specify syslog host address and port. Use --syslog-udp [host:port] format.");
				c.udpSyslogAddr = parseAddress(args[i + 1]);
				i++;
			} else if (args[i].equals("--syslog-level")) {
				try {
					verifyArgument(args, i, "Syslog level", "Specify syslog filter level: alert, info, or debug");
					c.syslogLevel = SyslogLevel.valueOf(args[i + 1].toUpperCase());
					i++;
				} catch (Throwable t) {
					throw new IllegalArgumentException("Invalid syslog level: " + args[i + 1]);
				}
			} else if (args[i].equals("--syslog-facility")) {
				verifyArgument(args, i, "Syslog facility",
						"Specify syslog facility. Value should be in the range of 0 to 23 inclusive.");

				try {
					c.syslogFacility = Integer.parseInt(args[i + 1]);
					if (c.syslogFacility < SYSLOG_FACILITY_KERNEL || c.syslogFacility > SYSLOG_FACILITY_LOCAL7)
						throw new IllegalArgumentException(
								"Syslog facility value should be in the range of 0 to 23 inclusive - " + args[i + 1]);

				} catch (NumberFormatException e) {
					throw new IllegalArgumentException("Value should be integer - " + args[i + 1]);
				}
				i++;
			} else if (args[i].equals("--rfc5424")) {
				c.rfc5424 = true;
			} else if (args[i].equals("--report-csv")) {
				c.reportCsv = true;
			} else if (args[i].equals("--report-json")) {
				c.reportJson = true;
			} else if (args[i].equals("--report-patch")) {
				c.reportPatch = true;
			} else if (args[i].equals("--report-path")) {
				verifyArgument(args, i, "Report path", "Specify report output path.");

				c.reportPath = args[i + 1];

				File reportFile = new File(c.reportPath);
				if (reportFile.exists())
					throw new IllegalArgumentException("File already exists - " + reportFile.getAbsolutePath());

				i++;
			} else if (args[i].equals("--report-dir")) {
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
			} else if (args[i].equals("--csv-log-path")) {
				verifyArgument(args, i, "CSV Log path", "Specify CSV log output path.");
				c.csvLogPath = new File(args[i + 1]);
				i++;
			} else if (args[i].equals("--json-log-path")) {
				verifyArgument(args, i, "JSON Log path", "Specify JSON log output path.");
				c.jsonLogPath = new File(args[i + 1]);
				i++;
			} else if (args[i].equals("--old-exit-code")) {
				c.oldExitCode = true;
			} else if (args[i].equals("--api-key")) {
				verifyArgument(args, i, "API key", "Specify API key of https://watch.logpresso.com.");
				c.apiKey = args[i + 1];
				if (c.apiKey.length() != 36)
					throw new IllegalArgumentException("API key should be GUID format: " + c.apiKey);

				try {
					UUID.fromString(c.apiKey);
				} catch (IllegalArgumentException e) {
					throw new IllegalArgumentException("API key should be GUID format: " + c.apiKey);
				}

				i++;
			} else if (args[i].equals("--http-proxy")) {
				verifyArgument(args, i, "API key", "Specify HTTP proxy IP address and port.");
				c.httpProxyAddr = parseHttpProxyAddress(args[i + 1]);
				System.setProperty("https.proxyHost", c.httpProxyAddr.getAddress().getHostAddress());
				System.setProperty("https.proxyPort", Integer.toString(c.httpProxyAddr.getPort()));

				i++;
			} else if (args[i].equals("--throttle")) {
				verifyArgument(args, i, "throttle", "Specify throttle number.");
				c.throttle = Integer.parseInt(args[i + 1]);
				i++;
			} else {
				if (args[i].startsWith("-"))
					throw new IllegalArgumentException("Unknown option: " + args[i]);

				String targetPath = c.fixPathTypo(args[i]);
				File dir = new File(targetPath);
				if (!dir.exists())
					throw new IllegalArgumentException("path not found: " + dir.getAbsolutePath());

				if (!dir.canRead())
					throw new IllegalArgumentException("no permission for " + dir.getAbsolutePath());

				c.targetPaths.add(targetPath);
			}
		}

		// check api key and connectivity
		if (c.getApiKey() != null)
			ReportGenerator.checkApiKey(c);

		// exclude iCloud and Dropbox by default
		String osName = System.getProperty("os.name");
		if (osName != null && osName.toLowerCase().startsWith("mac")) {
			c.excludePatterns.add("/Dropbox");
			c.excludePatterns.add("/Library/Mobile Documents");
		}

		// check conflict between --report-csv and --report-json
		if (c.reportCsv && c.reportJson && c.reportPath != null)
			throw new IllegalArgumentException(
					"Cannot use both --report-csv and --report-json options if --report-path is specified. Choose one.");

		// set --report-csv implicitly
		if (c.reportPath != null && (!c.reportCsv && !c.reportJson))
			c.reportCsv = true;

		if (c.reportDir != null && (!c.reportCsv && !c.reportJson))
			c.reportCsv = true;

		// verify drive letters
		c.verifyDriveLetters();

		// apply file system exclusion
		try {

			if (c.excludeFileSystems.isEmpty()) {
				for (String path : PartitionLoader.getExcludePaths(null))
					c.excludePathPrefixes.add(path);
			} else {
				for (String path : PartitionLoader.getExcludePaths(c.excludeFileSystems))
					c.excludePathPrefixes.add(path);
			}
		} catch (Exception e) {
			if (c.debug)
				e.printStackTrace();
		}

		// verify conflict option
		if (c.allDrives && !c.driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --all-drives and --drives options.");

		if (!c.allDrives && c.driveLetters.isEmpty() && c.includeFilePath == null && c.targetPaths.isEmpty()
				&& c.getRestorePath() == null)
			throw new IllegalArgumentException("Specify scan target path.");

		if (c.includeFilePath != null && c.allDrives)
			throw new IllegalArgumentException("Cannot specify both --all-drives and -f options.");

		if (c.includeFilePath != null && !c.driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --drives and -f options.");

		if (c.getRestorePath() != null) {
			// cannot use any other options
			rejectInvalidOptionForRestore(c);
		}

		return c;
	}

	private static InetSocketAddress parseHttpProxyAddress(String s) {
		int p = s.indexOf(':');
		if (p < 0)
			throw new IllegalArgumentException("Invalid http proxy option (missing port) - " + s);

		String host = s.substring(0, p);
		int port = -1;
		try {
			port = Integer.parseInt(s.substring(p + 1));
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid http proxy option (invalid port) - " + s);
		}

		if (port < 0 || port > 65535)
			throw new IllegalArgumentException("Invalid http proxy option (invalid port range) - " + s);

		InetAddress addr = null;
		try {
			addr = InetAddress.getByName(host);
		} catch (Throwable t) {
			throw new IllegalArgumentException("Invalid http proxy option (invalid host - " + t.getMessage() + ") - " + s);
		}

		return new InetSocketAddress(addr, port);
	}

	private static void rejectInvalidOptionForRestore(Configuration c) {
		if (!c.targetPaths.isEmpty())
			throw new IllegalArgumentException("Cannot specify scan target path with --restore option.");

		if (c.getIncludeFilePath() != null)
			throw new IllegalArgumentException("Cannot use --restore option with -f option.");

		if (c.isScanZip())
			throw new IllegalArgumentException("Cannot use --restore option with --scan-zip option.");

		if (c.isScanForLog4j1())
			throw new IllegalArgumentException("Cannot use --restore option with --scan-log4j1 option.");

		if (c.isScanForLogback())
			throw new IllegalArgumentException("Cannot use --restore option with --scan-logback option.");

		if (c.isFix())
			throw new IllegalArgumentException("Cannot use --restore option with --fix option.");

		if (c.isForce())
			throw new IllegalArgumentException("Cannot use --restore option with --force-fix option.");

		if (c.isAllDrives())
			throw new IllegalArgumentException("Cannot use --restore option with --all-drives option.");

		if (!c.getDriveLetters().isEmpty())
			throw new IllegalArgumentException("Cannot use --restore option with --drives option.");

		if (c.isReportCsv())
			throw new IllegalArgumentException("Cannot use --restore option with --report-csv option.");

		if (c.isReportJson())
			throw new IllegalArgumentException("Cannot use --restore option with --report-json option.");

		if (c.getReportDir() != null)
			throw new IllegalArgumentException("Cannot use --restore option with --report-dir option.");

		if (c.getReportPath() != null)
			throw new IllegalArgumentException("Cannot use --restore option with --report-path option.");

		if (c.getUdpSyslogAddr() != null)
			throw new IllegalArgumentException("Cannot use --restore option with --syslog-udp option.");
	}

	private static InetSocketAddress parseAddress(String s) {
		int portNum = 514;
		int p = s.indexOf(':');
		String addr = s;
		if (p > 0) {
			addr = s.substring(0, p);
			String port = s.substring(p + 1);

			try {
				portNum = Integer.parseInt(port);
				if (portNum <= 0 || portNum > 65535)
					throw new IllegalArgumentException("Syslog port number should be 1-65535: " + port);

			} catch (NumberFormatException e) {
				throw new IllegalArgumentException("Invalid syslog port number: " + port);
			}
		}

		return new InetSocketAddress(addr, portNum);
	}

	private static void verifyDriveLetter(String letter) {
		if (letter.length() > 1)
			throw new IllegalArgumentException("Invalid drive letter: " + letter);

		char c = letter.charAt(0);
		if (c < 'A' || c > 'Z')
			throw new IllegalArgumentException("Invalid drive letter: " + letter);
	}

	private static void verifyArgument(String[] args, int i, String name, String error) {
		if (args.length <= i + 1)
			throw new IllegalArgumentException(error);

		if (args[i + 1].startsWith("--"))
			throw new IllegalArgumentException(name + " should not starts with `--`.");
	}

	public Configuration(String[] args) {
		this.args = args;
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

	private void loadExcludePathPrefixes(File f) throws IOException {
		for (String line : IoUtils.loadLines(f)) {
			if (isWindows)
				line = line.toUpperCase();

			excludePathPrefixes.add(line);
		}
	}

	private void loadExcludeFilePaths(File f) throws IOException {
		for (String line : IoUtils.loadLines(f)) {
			if (isWindows)
				line = line.toLowerCase();

			excludeFilePaths.add(line);
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

	public String[] getArgs() {
		return args;
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

	public boolean isScanForCommonsText() {
		return scanForCommonsText;
	}

	public boolean isScanForLogback() {
		return scanForLogback;
	}

	public boolean isNoEmptyReport() {
		return noEmptyReport;
	}

	public File getCsvLogPath() {
		return csvLogPath;
	}

	public File getJsonLogPath() {
		return jsonLogPath;
	}

	public boolean isOldExitCode() {
		return oldExitCode;
	}

	public boolean isReportPatch() {
		return reportPatch;
	}

	public String getApiKey() {
		return apiKey;
	}

	public InetSocketAddress getHttpProxyAddr() {
		return httpProxyAddr;
	}

	public File getRestorePath() {
		return restorePath;
	}

	public File getBackupPath() {
		return backupPath;
	}

	public String getBackupExtension() {
		return backupExt;
	}

	public String getReportPath() {
		return reportPath;
	}

	public String getReportDir() {
		return reportDir;
	}

	public InetSocketAddress getUdpSyslogAddr() {
		return udpSyslogAddr;
	}

	public SyslogLevel getSyslogLevel() {
		return syslogLevel;
	}

	public int getSyslogFacility() {
		return syslogFacility;
	}

	public boolean isRfc5424() {
		return rfc5424;
	}

	public String getIncludeFilePath() {
		return includeFilePath;
	}

	public Set<File> getDriveLetters() {
		return driveLetters;
	}

	public List<String> getExcludePathPrefixes() {
		return excludePathPrefixes;
	}

	public List<String> getExcludePatterns() {
		return excludePatterns;
	}

	public Set<String> getExcludeFilePaths() {
		return excludeFilePaths;
	}

	public Set<String> getExcludeFileSystems() {
		return excludeFileSystems;
	}

	public int getThrottle() {
		return throttle;
	}
}
