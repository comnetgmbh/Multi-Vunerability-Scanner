package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Log4j2Scanner {
	private static final String BANNER = "Logpresso CVE-2021-44228 Vulnerability Scanner 2.1.0 (2021-12-17)";

	public enum Status {
		NOT_VULNERABLE, MITIGATED, POTENTIALLY_VULNERABLE, VULNERABLE;
	}

	private static final String POTENTIALLY_VULNERABLE = "N/A - potentially vulnerable";
	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
	private static final String LOG4j_CORE_POM_PROPS = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";

	private static final String LOG4J_12_CORE_POM_PROPS = "META-INF/maven/log4j/log4j/pom.properties";
	private static final String LOG4J_12_JMSAPPENDER = "org/apache/log4j/net/JMSAppender.class";

	private static final boolean isWindows = File.separatorChar == '\\';

	// status logging
	private long scanStartTime = 0;
	private long lastStatusLoggingTime = System.currentTimeMillis();
	private long lastStatusLoggingCount = 0;
	private File lastVisitDirectory = null;

	// results
	private long scanDirCount = 0;
	private long scanFileCount = 0;
	private int vulnerableFileCount = 0;
	private int mitigatedFileCount = 0;
	private int fixedFileCount = 0;
	private int potentiallyVulnerableFileCount = 0;

	private Set<File> vulnerableFiles = new LinkedHashSet<File>();

	// one archive file can be mapped to multiple entries
	private Map<File, List<ReportEntry>> fileReports = new TreeMap<File, List<ReportEntry>>();

	// options
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
	private boolean scanForlog4j1 = false;
	private String reportPath = null;
	private Set<File> driveLetters = new TreeSet<File>();
	private List<String> excludePaths = new ArrayList<String>();
	private List<String> excludePatterns = new ArrayList<String>();
	private Set<String> excludeFileSystems = new HashSet<String>();

	public static void main(String[] args) {
		try {
			Log4j2Scanner scanner = new Log4j2Scanner();
			scanner.run(args);
			System.exit(scanner.vulnerableFileCount + scanner.potentiallyVulnerableFileCount);
		} catch (Throwable t) {
			System.out.println("Error: " + t.getMessage());
			System.exit(-1);
		}
	}

	public void run(String[] args) throws IOException {
		if (args.length < 1) {
			pringUsage();
			return;
		}
		parseArguments(args);

		if (fix && !force) {
			try {
				System.out.print("This command will remove JndiLookup.class from log4j2-core binaries. Are you sure [y/N]? ");
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String answer = br.readLine();
				if (!answer.equalsIgnoreCase("y")) {
					System.out.println("interrupted");
					return;
				}
			} catch (Throwable t) {
				System.out.println("error: " + t.getMessage());
				return;
			}
		}

		run();
	}

	private void pringUsage() {
		System.out.println(BANNER);
		System.out.println("Usage: log4j2-scan [--fix] target_path1, target_path2");
		System.out.println("");
		System.out.println("--fix");
		System.out.println("\tBackup original file and remove JndiLookup.class from JAR recursively.");
		System.out.println("--force-fix");
		System.out.println("\tDo not prompt confirmation. Don't use this option unless you know what you are doing.");
		System.out.println("--debug");
		System.out.println("\tPrint exception stacktrace for debugging.");
		System.out.println("--trace");
		System.out.println("\tPrint all directories and files while scanning.");
		System.out.println("--silent");
		System.out.println("\tDo not print anything until scan is completed.");
		System.out.println("--scan-log4j1");
		System.out.println("\tEnables scanning for log4j 1 versions.");
		System.out.println("--scan-zip");
		System.out.println("\tScan also .zip extension files. This option may slow down scanning.");
		System.out.println("--no-symlink");
		System.out.println("\tDo not detect symlink as vulnerable file.");
		System.out.println("--exclude [path_prefix]");
		System.out.println("\tExclude specified paths. You can specify multiple --exclude [path_prefix] pairs");
		System.out.println("--exclude-config [file_path]");
		System.out.println(
				"\tSpecify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.");
		System.out.println("--exclude-pattern [pattern]");
		System.out.println(
				"\tExclude specified paths by pattern. You can specify multiple --exclude-pattern [pattern] pairs (non regex)");
		System.out.println("--exclude-fs nfs,tmpfs");
		System.out.println("\tExclude paths by file system type. nfs, tmpfs, devtmpfs, and iso9660 is ignored by default.");
		System.out.println("--all-drives");
		System.out.println("\tScan all drives on Windows");
		System.out.println("--drives c,d");
		System.out.println("\tScan specified drives on Windows. Spaces are not allowed here.");
		System.out.println("--report-csv");
		System.out.println(
				"\tGenerate log4j2_scan_report_yyyyMMdd_HHmmss.csv in working directory if not specified otherwise via --report-path [path]");
		System.out.println("--report-path");
		System.out.println("\tSpecify report output path.");
		System.out.println("\tSpecify report output path. (Implies --report-csv)");
		System.out.println("--help");
		System.out.println("\tPrint this help.");
	}

	private void parseArguments(String[] args) throws IOException {
		int i = 0;
		for (; i < args.length; i++) {
			if (args[i].equals("--fix")) {
				fix = true;
			} else if (args[i].equals("--force-fix")) {
				fix = true;
				force = true;
			} else if (args[i].equals("--debug")) {
				debug = true;
			} else if (args[i].equals("--trace")) {
				trace = true;
			} else if (args[i].equals("--silent")) {
				silent = true;
			} else if (args[i].equals("--scan-zip")) {
				scanZip = true;
			} else if (args[i].equals("--no-symlink")) {
				noSymlink = true;
			} else if (args[i].equals("--scan-log4j1")) {
				scanForlog4j1 = true;
			} else if (args[i].equals("--help") || args[i].equals("-h")) {
				pringUsage();
				System.exit(0);
			} else if (args[i].equals("--all-drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--all-drives is supported on Windows only.");

				allDrives = true;
			} else if (args[i].equals("--drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--drives is supported on Windows only.");

				if (args.length > i + 1) {
					for (String letter : args[i + 1].split(",")) {
						letter = letter.trim().toUpperCase();
						if (letter.length() == 0)
							continue;

						if (letter.length() > 1)
							throw new IllegalArgumentException("Invalid drive letter: " + letter);

						char c = letter.charAt(0);
						if (c < 'A' || c > 'Z')
							throw new IllegalArgumentException("Invalid drive letter: " + letter);

						driveLetters.add(new File(letter + ":\\"));
					}
				} else {
					throw new IllegalArgumentException("Specify drive letters.");
				}

				i++;
			} else if (args[i].equals("--exclude")) {
				if (args.length > i + 1) {
					String path = args[i + 1];
					if (path.startsWith("--")) {
						throw new IllegalArgumentException("Path should not starts with `--`. Specify exclude file path.");
					}

					if (isWindows)
						path = path.toUpperCase();

					excludePaths.add(path);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude file path.");
				}
			} else if (args[i].equals("--exclude-pattern")) {
				if (args.length > i + 1) {
					String pattern = args[i + 1];
					if (pattern.startsWith("--")) {
						throw new IllegalArgumentException("Pattern should not starts with `--`. Specify exclude pattern.");
					}

					if (isWindows)
						pattern = pattern.toUpperCase();

					excludePatterns.add(pattern);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude pattern.");
				}
			} else if (args[i].equals("--exclude-config")) {
				if (args.length > i + 1) {
					String path = args[i + 1];
					if (path.startsWith("--")) {
						throw new IllegalArgumentException("Path should not starts with `--`. Specify exclude file path.");
					}

					File f = new File(path);
					if (!f.exists() || !f.canRead())
						throw new IllegalArgumentException("Cannot read exclude config file: " + f.getAbsolutePath());

					loadExcludePaths(f);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude file path.");
				}
			} else if (args[i].equals("--exclude-fs")) {
				if (args.length > i + 1) {
					for (String type : args[i + 1].split(",")) {
						type = type.trim().toLowerCase();
						if (type.length() == 0)
							continue;

						excludeFileSystems.add(type);
					}
				} else {
					throw new IllegalArgumentException("Specify file system types.");
				}

				i++;

			} else if (args[i].equals("--report-csv")) {
				reportCsv = true;
			} else if (args[i].equals("--report-path")) {
				reportCsv = true;

				if (args.length > i + 1) {
					String pattern = args[i + 1];
					if (pattern.startsWith("--"))
						throw new IllegalArgumentException("Report path should not starts with `--`.");

					reportPath = args[i + 1];

					File reportFile = new File(reportPath);
					if (reportFile.exists())
						throw new IllegalArgumentException("File already exists - " + reportFile.getAbsolutePath());

					i++;
				} else {
					throw new IllegalArgumentException("Specify report output path.");
				}
			} else {
				String targetPath = fixPathTypo(args[i]);
				File dir = new File(targetPath);
				if (!dir.exists())
					throw new IllegalArgumentException("path not found: " + dir.getAbsolutePath());

				if (!dir.canRead())
					throw new IllegalArgumentException("no permission for " + dir.getAbsolutePath());

				targetPaths.add(targetPath);
			}
		}

		// verify drive letters
		verifyDriveLetters();

		// apply file system exclusion
		try {

			if (excludeFileSystems.isEmpty()) {
				for (String path : PartitionLoader.getExcludePaths(null))
					excludePaths.add(path);
			} else {
				for (String path : PartitionLoader.getExcludePaths(excludeFileSystems))
					excludePaths.add(path);
			}
		} catch (Exception e) {
			if (debug)
				e.printStackTrace();
		}

		// verify conflict option
		if (allDrives && !driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --all-drives and --drives options.");

		if (!allDrives && driveLetters.isEmpty() && targetPaths.isEmpty())
			throw new IllegalArgumentException("Specify scan target path.");
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
			ensureClose(fis);
			ensureClose(br);
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

	public void run() throws IOException {
		scanStartTime = System.currentTimeMillis();
		System.out.println(BANNER);
		try {
			if (allDrives) {
				List<String> allDrives = new ArrayList<String>();
				for (Partition drive : PartitionLoader.getPartitions()) {
					if (isExcluded(drive.getPath()))
						continue;

					allDrives.add(drive.getPath());
				}

				System.out.println("Scanning drives: " + join(allDrives, ", "));
				System.out.println("");

				for (String drivePath : allDrives)
					traverse(new File(drivePath));
			} else if (!driveLetters.isEmpty()) {
				for (File drive : driveLetters)
					traverse(drive);
			} else {

				String excludeMsg = "";
				if (!excludePaths.isEmpty())
					excludeMsg = " (without " + join(excludePaths, ", ") + ")";

				String targetMsg = join(targetPaths, ", ");
				System.out.println("Scanning directory: " + targetMsg + excludeMsg);

				for (String targetPath : targetPaths) {
					File f = new File(targetPath);
					traverse(f);
				}
			}

			if (fix)
				fix(trace);

			writeReportFile();

		} finally {
			long elapsed = System.currentTimeMillis() - scanStartTime;
			System.out.println();
			System.out.println("Scanned " + scanDirCount + " directories and " + scanFileCount + " files");
			System.out.println("Found " + vulnerableFileCount + " vulnerable files");
			System.out.println("Found " + potentiallyVulnerableFileCount + " potentially vulnerable files");
			System.out.println("Found " + mitigatedFileCount + " mitigated files");
			if (fix)
				System.out.println("Fixed " + fixedFileCount + " vulnerable files");

			System.out.printf("Completed in %.2f seconds\n", elapsed / 1000.0);
		}
	}

	private void writeReportFile() {
		if (!reportCsv)
			return;

		SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmss");
		File f = new File("log4j2_scan_report_" + df.format(new Date()) + ".csv");
		if (reportPath != null) {
			f = new File(reportPath);

			// double check
			if (f.exists()) {
				System.out.println("Cannot write report file. File already exsts: " + f.getAbsolutePath());
				return;
			}
		}

		FileOutputStream csvStream = null;
		try {
			csvStream = new FileOutputStream(f);
			String header = String.format("Hostname,Path,Entry,Version,Status,Fixed,Detected at%n");
			csvStream.write(header.getBytes("utf-8"));

			String hostname = getHostname();
			if (hostname == null)
				hostname = "";

			for (File file : fileReports.keySet()) {
				for (ReportEntry entry : fileReports.get(file)) {
					String line = entry.getCsvLine();
					line = hostname + "," + line;
					csvStream.write(line.getBytes("utf-8"));
				}
			}

		} catch (IOException e) {
			throw new IllegalStateException("cannot open csv report file: " + e.getMessage(), e);
		} finally {
			ensureClose(csvStream);
		}

	}

	private void fix(boolean trace) {
		if (!vulnerableFiles.isEmpty())
			System.out.println("");

		for (File f : vulnerableFiles) {
			File symlinkFile = null;
			String symlinkMsg = "";

			if (isSymlink(f)) {
				try {
					symlinkFile = f;
					f = symlinkFile.getCanonicalFile();
					symlinkMsg = " (from symlink " + symlinkFile.getAbsolutePath() + ")";
				} catch (IOException e) {
					// unreachable (already known symlink)
				}
			}

			if (trace)
				System.out.printf("Patching %s%s%n", f.getAbsolutePath(), symlinkMsg);

			File backupFile = new File(f.getAbsolutePath() + ".bak");

			if (backupFile.exists()) {
				System.out.println("Error: Cannot create backup file. .bak File already exists. Skipping " + f.getAbsolutePath());
				continue;
			}

			// check lock first
			if (isLocked(f)) {
				System.out.println("Error: File is locked by other process. Skipping " + f.getAbsolutePath());
				continue;
			}

			if (copyAsIs(f, backupFile)) {
				// keep inode as is for symbolic link
				if (!truncate(f)) {
					System.out.println("Error: Cannot patch locked file " + f.getAbsolutePath());
					backupFile.delete();
					continue;
				}

				if (copyExceptJndiLookup(backupFile, f)) {
					fixedFileCount++;

					System.out.printf("Fixed: %s%s%n", f.getAbsolutePath(), symlinkMsg);

					// update fixed status
					List<ReportEntry> entries = fileReports.get(f);
					for (ReportEntry entry : entries)
						entry.setFixed(true);
				} else {
					// rollback operation
					copyAsIs(backupFile, f);
				}
			}
		}
	}

	private boolean isLocked(File f) {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			FileLock lock = raf.getChannel().lock();
			lock.release();
			return false;
		} catch (Throwable t) {
			return true;
		} finally {
			ensureClose(raf);
		}
	}

	private boolean truncate(File f) {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			raf.setLength(0);
			return true;
		} catch (Throwable t) {
			return false;
		} finally {
			ensureClose(raf);
		}
	}

	private boolean copyAsIs(File srcFile, File dstFile) {
		FileInputStream is = null;
		FileOutputStream os = null;

		try {
			is = new FileInputStream(srcFile);
			os = new FileOutputStream(dstFile);

			byte[] buf = new byte[32768];
			while (true) {
				int len = is.read(buf);
				if (len < 0)
					break;

				os.write(buf, 0, len);
			}

			return true;
		} catch (Throwable t) {
			System.out.println("Error: Cannot copy file " + srcFile.getAbsolutePath() + " - " + t.getMessage());
			return false;
		} finally {
			ensureClose(is);
			ensureClose(os);
		}
	}

	private boolean copyExceptJndiLookup(File srcFile, File dstFile) {
		Set<String> entryNames = new HashSet<String>();
		ZipFile srcZipFile = null;
		ZipOutputStream zos = null;

		try {
			srcZipFile = new ZipFile(srcFile);
			zos = new ZipOutputStream(new FileOutputStream(dstFile));
			zos.setMethod(ZipOutputStream.STORED);
			zos.setLevel(Deflater.NO_COMPRESSION);

			Enumeration<?> e = srcZipFile.entries();
			while (e.hasMoreElements()) {
				ZipEntry entry = (ZipEntry) e.nextElement();

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					continue;

				// skip if duplicated
				if (!entryNames.add(entry.getName()))
					continue;

				if (entry.isDirectory()) {
					ZipEntry newEntry = new ZipEntry(entry.getName());
					newEntry.setMethod(ZipEntry.STORED);
					newEntry.setCompressedSize(0);
					newEntry.setSize(0);
					newEntry.setCrc(0);

					zos.putNextEntry(newEntry);

					continue;
				}

				copyZipEntry(srcZipFile, entry, zos);
			}

			return true;
		} catch (Throwable t) {
			if (debug)
				t.printStackTrace();

			System.out.println(
					"Error: Cannot fix file (" + t.getMessage() + "). rollback original file " + dstFile.getAbsolutePath());
			return false;
		} finally {
			ensureClose(srcZipFile);
			ensureClose(zos);
		}
	}

	private void copyZipEntry(ZipFile srcZipFile, ZipEntry zipEntry, ZipOutputStream zos) throws IOException {
		InputStream is = null;
		try {
			is = srcZipFile.getInputStream(zipEntry);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			if (isScanTarget(zipEntry.getName())) {
				copyNestedJar(is, bos);
			} else {
				byte[] buf = new byte[32768];
				while (true) {
					int len = is.read(buf);
					if (len < 0)
						break;

					bos.write(buf, 0, len);
				}
			}

			byte[] tempBuf = bos.toByteArray();
			ZipEntry entry = new ZipEntry(zipEntry.getName());
			entry.setMethod(ZipEntry.STORED);
			entry.setCompressedSize(tempBuf.length);
			entry.setSize(tempBuf.length);
			entry.setCrc(computeCrc32(tempBuf));

			// caller should check duplicated entry
			zos.putNextEntry(entry);
			transfer(new ByteArrayInputStream(tempBuf), zos);

		} finally {
			ensureClose(is);
		}
	}

	private void transfer(InputStream is, OutputStream os) throws IOException {
		byte[] buf = new byte[32768];
		while (true) {
			int len = is.read(buf);
			if (len < 0)
				break;

			os.write(buf, 0, len);
		}
	}

	private void copyNestedJar(InputStream is, OutputStream os) throws IOException {
		// check duplicated entry exception
		Set<String> entryNames = new HashSet<String>();

		ZipInputStream zis = null;
		ZipOutputStream zos = null;
		try {
			zis = new ZipInputStream(new DummyInputStream(is));
			zos = new ZipOutputStream(os);

			while (true) {
				ZipEntry zipEntry = zis.getNextEntry();
				if (zipEntry == null)
					break;

				if (zipEntry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					continue;

				if (zipEntry.isDirectory()) {
					ZipEntry entry = new ZipEntry(zipEntry.getName());

					if (entryNames.add(entry.getName()))
						zos.putNextEntry(entry);

					continue;
				}

				// fix recursively
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				if (isScanTarget(zipEntry.getName())) {
					copyNestedJar(zis, bos);
				} else {
					byte[] buf = new byte[32768];
					while (true) {
						int len = zis.read(buf);
						if (len < 0)
							break;

						bos.write(buf, 0, len);
					}
				}

				byte[] outputBuf = bos.toByteArray();
				ZipEntry entry = new ZipEntry(zipEntry.getName());

				if (entryNames.add(entry.getName())) {
					zos.putNextEntry(entry);
					transfer(new ByteArrayInputStream(outputBuf), zos);
				}
			}
		} finally {
			ensureClose(zis);

			if (zos != null)
				zos.finish();
		}
	}

	private long computeCrc32(byte[] buf) {
		CRC32 crc = new CRC32();
		crc.update(buf, 0, buf.length);
		return crc.getValue();
	}

	private void traverse(File f) {
		if (!silent && canStatusReporting())
			printScanStatus();

		String path = f.getAbsolutePath();

		if (f.isDirectory()) {
			lastVisitDirectory = f;

			if (isExcluded(path)) {
				if (trace)
					System.out.println("Skipping excluded directory: " + path);

				return;
			}

			if (isSymlink(f)) {
				if (trace)
					System.out.println("Skipping symlink: " + path);

				return;
			}

			if (isExcludedDirectory(path)) {
				if (trace)
					System.out.println("Skipping directory: " + path);

				return;
			}

			if (trace)
				System.out.println("Scanning directory: " + path);

			scanDirCount++;

			File[] files = f.listFiles();
			if (files == null)
				return;

			for (File file : files) {
				traverse(file);
			}
		} else {
			scanFileCount++;

			if (noSymlink && isSymlink(f)) {
				if (trace)
					System.out.println("Skipping symlink: " + path);
			} else if (isScanTarget(path)) {
				if (trace)
					System.out.println("Scanning file: " + path);

				scanJarFile(f, fix);
			} else {
				if (trace)
					System.out.println("Skipping file: " + path);
			}
		}
	}

	private void printScanStatus() {
		long now = System.currentTimeMillis();
		int elapsed = (int) ((now - scanStartTime) / 1000);
		System.out.printf("Running scan (%ds): scanned %d directories, %d files, last visit: %s%n", elapsed, scanDirCount,
				scanFileCount, lastVisitDirectory.getAbsolutePath());

		lastStatusLoggingCount = scanFileCount;
		lastStatusLoggingTime = System.currentTimeMillis();
	}

	private boolean canStatusReporting() {
		// check scan file count to reduce system call overhead
		return scanFileCount - lastStatusLoggingCount >= 1000 && System.currentTimeMillis() - lastStatusLoggingTime >= 10000;
	}

	private boolean isSymlink(File f) {
		// use JDK7 feature
		return Files.isSymbolicLink(f.toPath());
	}

	private boolean isExcludedDirectory(String path) {
		if (isWindows && path.toUpperCase().indexOf("$RECYCLE.BIN") == 3)
			return true;

		return (path.equals("/proc") || path.startsWith("/proc/")) || (path.equals("/sys") || path.startsWith("/sys/"))
				|| (path.equals("/dev") || path.startsWith("/dev/")) || (path.equals("/run") || path.startsWith("/run/"))
				|| (path.equals("/var/run") || path.startsWith("/var/run/"));
	}

	protected void scanJarFile(File jarFile, boolean fix) {
		ZipFile zipFile = null;
		InputStream is = null;
		boolean vulnerable = false;
		boolean mitigated = false;
		boolean potentiallyVulnerable = false;
		try {
			zipFile = new ZipFile(jarFile);

			Status status = checkLog4j2Version(jarFile, fix, zipFile);
			vulnerable = (status == Status.VULNERABLE);
			mitigated = (status == Status.MITIGATED);
			potentiallyVulnerable = (status == Status.POTENTIALLY_VULNERABLE);

			if (scanForlog4j1) {
				Status status_12 = checkLog4j1Version(jarFile, zipFile);
				potentiallyVulnerable |= (status_12 == Status.POTENTIALLY_VULNERABLE);
			}

			// scan nested jar files
			Enumeration<?> e = zipFile.entries();
			while (e.hasMoreElements()) {
				ZipEntry zipEntry = (ZipEntry) e.nextElement();
				if (!zipEntry.isDirectory() && isScanTarget(zipEntry.getName())) {
					Status nestedJarStatus = scanNestedJar(jarFile, zipFile, zipEntry);
					vulnerable |= (nestedJarStatus == Status.VULNERABLE);
					mitigated |= (nestedJarStatus == Status.MITIGATED);
					potentiallyVulnerable |= (nestedJarStatus == Status.POTENTIALLY_VULNERABLE);
				}
			}

			if (vulnerable)
				vulnerableFileCount++;
			else if (mitigated)
				mitigatedFileCount++;
			else if (potentiallyVulnerable)
				potentiallyVulnerableFileCount++;

			if (fix && vulnerable)
				vulnerableFiles.add(jarFile);

		} catch (ZipException e) {
			// ignore broken zip file
			System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
		} catch (IllegalArgumentException e) {
			if (e.getMessage().equals("MALFORMED")) {
				System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
			} else {
				System.out.printf("Scan error: '%s' on file: %s%n", e.getMessage(), jarFile);
				if (debug)
					e.printStackTrace();
			}
		} catch (Throwable t) {
			System.out.printf("Scan error: '%s' on file: %s%n", t.getMessage(), jarFile);
			if (debug)
				t.printStackTrace();
		} finally {
			ensureClose(is);
			ensureClose(zipFile);
		}
	}

	protected Status checkLog4j2Version(File jarFile, boolean fix, ZipFile zipFile) throws IOException {
		ZipEntry entry = zipFile.getEntry(LOG4j_CORE_POM_PROPS);
		if (entry == null) {
			// Check for existence of JndiLookup.class; e.g. somebody repacked the entries
			// of the jars
			entry = zipFile.getEntry(JNDI_LOOKUP_CLASS_PATH);
			if (entry != null) {
				printDetectionForLog4j2(jarFile, null, POTENTIALLY_VULNERABLE, false, true);
				return Status.POTENTIALLY_VULNERABLE;
			}
			return Status.NOT_VULNERABLE;
		}

		InputStream is = null;
		try {
			is = zipFile.getInputStream(entry);

			String version = loadVulnerableLog4jVersion(is);
			if (version != null) {
				boolean mitigated = zipFile.getEntry(JNDI_LOOKUP_CLASS_PATH) == null;
				printDetectionForLog4j2(jarFile, null, version, mitigated, false);
				return mitigated ? Status.MITIGATED : Status.VULNERABLE;
			}

			return Status.NOT_VULNERABLE;
		} finally {
			ensureClose(is);
		}
	}

	private Status checkLog4j1Version(File jarFile, ZipFile zipFile) throws IOException {
		ZipEntry entry = zipFile.getEntry(LOG4J_12_CORE_POM_PROPS);
		if (entry == null) {
			entry = zipFile.getEntry(LOG4J_12_JMSAPPENDER);
			if (entry != null) {
				String path = jarFile.getAbsolutePath();
				printDetectionForLog4j1(jarFile, null, POTENTIALLY_VULNERABLE);
				return Status.POTENTIALLY_VULNERABLE;
			}
			return Status.NOT_VULNERABLE;
		}

		InputStream is = null;
		try {
			is = zipFile.getInputStream(entry);

			String version = loadVulnerableLog4j1(is);
			if (version != null) {
				boolean jmsAppender = zipFile.getEntry(LOG4J_12_JMSAPPENDER) != null;
				if (jmsAppender) {
					String path = jarFile.getAbsolutePath();
					printDetectionForLog4j1(jarFile, null, version);
				}
				return jmsAppender ? Status.POTENTIALLY_VULNERABLE : Status.NOT_VULNERABLE;
			}

			return Status.NOT_VULNERABLE;
		} finally {
			ensureClose(is);
		}
	}

	private void printDetectionForLog4j2(File jarFile, List<String> pathChain, String version, boolean mitigated,
			boolean potential) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null)
			path += " (" + toString(pathChain) + ")";

		String msg = potential ? "[?]" : "[*]";

		String cve = "CVE-2021-44228";
		if (version.startsWith("2.15."))
			cve = "CVE-2021-45046";

		msg += " Found " + cve + " (log4j 2.x) vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);
		addReport(jarFile, pathChain, version, mitigated, potential);
	}

	private void printDetectionForLog4j1(File jarFile, List<String> pathChain, String version) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null)
			path += " (" + toString(pathChain) + ")";

		String msg = "[?] Found CVE-2021-4104  (log4j 1.2) vulnerability in " + path + ", log4j " + version;
		System.out.println(msg);

		addReport(jarFile, pathChain, version, false, true);
	}

	private Status scanNestedJar(File fatJarFile, ZipFile zipFile, ZipEntry zipEntry) {
		InputStream is = null;
		try {
			is = zipFile.getInputStream(zipEntry);
			List<String> pathChain = new ArrayList<String>();
			pathChain.add(zipEntry.getName());
			Status status = scanStream(fatJarFile, is, pathChain);
			return status;
		} catch (IOException e) {
			String msg = "cannot scan nested jar " + fatJarFile.getAbsolutePath() + ", entry " + zipEntry.getName();
			throw new IllegalStateException(msg, e);
		} finally {
			ensureClose(is);
		}
	}

	private Status scanStream(File fatJarFile, InputStream is, List<String> pathChain) {
		ZipInputStream zis = null;
		Status maxNestedJarStatus = Status.NOT_VULNERABLE;
		String vulnerableVersion2 = null;
		String vulnerableVersion1 = null;
		boolean mitigated = true;
		boolean pomFound = false;
		boolean foundJmsAppender = false;

		try {
			zis = new ZipInputStream(new DummyInputStream(is));

			while (true) {
				ZipEntry entry = zis.getNextEntry();
				if (entry == null)
					break;

				if (entry.getName().equals(LOG4j_CORE_POM_PROPS)) {
					vulnerableVersion2 = loadVulnerableLog4jVersion(zis);
					pomFound = true;
				}

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH)) {
					mitigated = false;
				}

				if (scanForlog4j1) {
					if (entry.getName().equals(LOG4J_12_CORE_POM_PROPS)) {
						vulnerableVersion1 = loadVulnerableLog4j1(zis);
					}
					if (entry.getName().equals(LOG4J_12_JMSAPPENDER)) {
						foundJmsAppender = true;
					}
				}

				if (isScanTarget(entry.getName())) {
					pathChain.add(entry.getName());
					Status nestedStatus = scanStream(fatJarFile, zis, pathChain);
					if (nestedStatus.ordinal() > maxNestedJarStatus.ordinal())
						maxNestedJarStatus = nestedStatus;

					pathChain.remove(pathChain.size() - 1);
				}
			}

			if (vulnerableVersion2 != null) {
				printDetectionForLog4j2(fatJarFile, pathChain, vulnerableVersion2, mitigated, false);
				Status selfStatus = mitigated ? Status.MITIGATED : Status.VULNERABLE;
				return selfStatus.ordinal() > maxNestedJarStatus.ordinal() ? selfStatus : maxNestedJarStatus;
			}

			if (!mitigated && !pomFound) {
				printDetectionForLog4j2(fatJarFile, pathChain, POTENTIALLY_VULNERABLE, false, true);

				if (maxNestedJarStatus.ordinal() > Status.POTENTIALLY_VULNERABLE.ordinal())
					return maxNestedJarStatus;

				return Status.POTENTIALLY_VULNERABLE;
			}

			if (foundJmsAppender) {
				String path = fatJarFile + " (" + toString(pathChain) + ")";
				if (vulnerableVersion1 != null) {
					printDetectionForLog4j1(fatJarFile, pathChain, vulnerableVersion1);
					return Status.POTENTIALLY_VULNERABLE;
				} else {
					printDetectionForLog4j1(fatJarFile, pathChain, POTENTIALLY_VULNERABLE);
					return Status.POTENTIALLY_VULNERABLE;
				}
			}

			if (maxNestedJarStatus != Status.NOT_VULNERABLE)
				return maxNestedJarStatus;

			return Status.NOT_VULNERABLE;
		} catch (IOException e) {
			// ignore WinRAR
			String entryName = pathChain.get(pathChain.size() - 1);
			if (entryName.toLowerCase().endsWith(".rar"))
				return Status.NOT_VULNERABLE;

			String msg = "cannot scan nested jar " + fatJarFile.getAbsolutePath() + ", path " + toString(pathChain);
			throw new IllegalStateException(msg, e);
		} finally {
			ensureClose(zis);
		}
	}

	private String toString(List<String> pathChain) {
		if (pathChain == null)
			return "";

		return join(pathChain, " > ");
	}

	private String join(List<String> tokens, String separator) {
		StringBuilder sb = new StringBuilder();
		int i = 0;

		for (String path : tokens) {
			if (i++ != 0)
				sb.append(separator);
			sb.append(path);
		}

		return sb.toString();
	}

	private String loadVulnerableLog4jVersion(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("org.apache.logging.log4j") && artifactId.equals("log4j-core")) {
			String ver = version;
			int p = version.indexOf('-');
			if (p > 0)
				ver = version.substring(0, p);

			String[] tokens = ver.split("\\.");
			int major = Integer.parseInt(tokens[0]);
			int minor = Integer.parseInt(tokens[1]);
			int patch = 0;

			// e.g. version 2.0 has only 2 tokens
			if (tokens.length > 2)
				patch = Integer.parseInt(tokens[2]);

			if (isVulnerable(major, minor, patch))
				return version;
		}

		return null;
	}

	private String loadVulnerableLog4j1(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");
		return version;
	}

	private boolean isScanTarget(String path) {
		String loweredPath = path.toLowerCase();
		if (scanZip && loweredPath.endsWith(".zip"))
			return true;

		// ear = Java EE archive, aar = Android archive
		// rar = Java EE resource adapter archive (not WinRAR)
		return loweredPath.endsWith(".jar") || loweredPath.endsWith(".war") || loweredPath.endsWith(".ear")
				|| loweredPath.endsWith(".aar") || loweredPath.endsWith(".rar");
	}

	private boolean isExcluded(String path) {
		if (isWindows)
			path = path.toUpperCase();

		for (String excludePath : excludePaths) {
			if (path.startsWith(excludePath))
				return true;
		}

		for (String excludePattern : excludePatterns) {
			if (path.contains(excludePattern))
				return true;
		}

		return false;
	}

	private boolean isVulnerable(int major, int minor, int patch) {
		// treat 2.12.2 as non-vulnerable for JDK7
		if (major == 2 && minor == 12 && patch >= 2)
			return false;

		return major == 2 && minor < 16;
	}

	private void addReport(File jarFile, List<String> pathChain, String version, boolean mitigated, boolean potential) {
		List<ReportEntry> entries = fileReports.get(jarFile);
		if (entries == null) {
			entries = new ArrayList<ReportEntry>();
			fileReports.put(jarFile, entries);
		}

		Status status = Status.VULNERABLE;
		if (mitigated)
			status = Status.MITIGATED;
		else if (potential)
			status = Status.POTENTIALLY_VULNERABLE;

		ReportEntry entry = new ReportEntry(jarFile, toString(pathChain), version, status);
		entries.add(entry);
	}

	private void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}

	private void ensureClose(ZipFile zipFile) {
		if (zipFile != null) {
			try {
				zipFile.close();
			} catch (Throwable t) {
			}
		}
	}

	private static String getHostname() {
		// Try to fetch hostname without DNS resolving for closed network
		if (isWindows) {
			return System.getenv("COMPUTERNAME");
		} else {
			return System.getenv("HOSTNAME");
		}
	}
}
