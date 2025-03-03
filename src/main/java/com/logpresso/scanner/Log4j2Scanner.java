package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import com.logpresso.scanner.utils.FileUtils;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipUtils;

public class Log4j2Scanner {
	public static final String VERSION = "3.0.2";
	public static final String RELEASE_DATE = "2022-02-14";
	public static final String BANNER = "Logpresso CVE-2021-44228 Vulnerability Scanner " + VERSION + " (" + RELEASE_DATE + ")";

	protected static final boolean isWindows = File.separatorChar == '\\';

	protected Configuration config;
	protected Metrics metrics;
	protected Detector detector;
	protected LogGenerator logGenerator;


	public int run(Configuration config) throws Exception {
		this.config = config;
		metrics = new Metrics(config.getThrottle());

		if (config.isFix() && !config.isForce()) {
			try {
				if (config.isScanForLog4j1()) {
					System.out.print("This command will remove JndiLookup.class from log4j2-core binaries and "
							+ "remove JMSSink.class, JMSAppender.class, SocketServer.class, SMTPAppender.class, SMTPAppender$1.class, JDBCAppender.class, org.apache.log4j.chainsaw package "
							+ "from log4j1-core binaries. Are you sure [y/N]? ");
				} else {
					System.out.print("This command will remove JndiLookup.class from log4j2-core binaries. Are you sure [y/N]? ");
				}
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String answer = br.readLine();
				if (!answer.equalsIgnoreCase("y")) {
					System.out.println("interrupted");
					return 0;
				}
			} catch (Throwable t) {
				System.out.println("error: " + t.getMessage());
				return -1;
			}
		}

		if (config.getRestorePath() != null) {
			return restore(config.getRestorePath());
		} else {
			return scanAndFix();
		}
	}

	public int restore(File backupFile) throws IOException {

		System.out.println("");

		ZipInputStream zis = null;
		try {
			zis = new ZipInputStream(new FileInputStream(backupFile));
			while (true) {
				ZipEntry entry = zis.getNextEntry();
				if (entry == null)
					break;

				String path = entry.getName();
				if (isWindows)
					path = path.charAt(0) + ":" + path.substring(1);

				File targetFile = new File(path);
				restore(zis, targetFile);
			}
		} finally {
			IoUtils.ensureClose(zis);
		}
		return 0;
	}

	protected void restore(InputStream is, File targetFile) {
		// set writable if file is read-only
		boolean readonlyFile = false;
		if (!targetFile.canWrite()) {
			readonlyFile = true;
			if (!targetFile.setWritable(true)) {
				reportError(targetFile, "No write permission. Cannot remove read-only attribute");
				return;
			}
		}

		// copy backup file content
		FileOutputStream fos = null;
		boolean lockError = true;
		boolean truncateError = true;
		try {
			// check lock first
			FileUtils.checkLock(targetFile);
			lockError = false;

			long originalBytes = targetFile.length();

			// keep inode as is for symbolic link
			FileUtils.truncate(targetFile);
			truncateError = false;

			fos = new FileOutputStream(targetFile);
			long transferBytes = FileUtils.transfer(is, fos);

			DecimalFormat formatter = new DecimalFormat("###,###");
			String before = formatter.format(originalBytes);
			String after = formatter.format(transferBytes);
			System.out.printf("Restored: %s (%s => %s bytes)%n", targetFile.getAbsolutePath(), before, after);
		} catch (Throwable t) {
			if (lockError) {
				System.out.println("Cannot lock file " + t.getMessage());
			} else if (truncateError) {
				System.out.println("Cannot truncate file " + t.getMessage());
			} else {
				System.out.println("Cannot restore file " + t.getMessage());
			}

			if (config.isDebug())
				t.printStackTrace();

		} finally {
			IoUtils.ensureClose(fos);

			// restore read only attribute
			if (readonlyFile) {
				if (!targetFile.setReadOnly())
					System.out.println("Error: File cannot be set as read only - " + targetFile.getAbsolutePath());
			}
		}
	}

	public int scanAndFix() throws IOException {
		System.out.println("scanAndFix with " + this.getClass().getSimpleName());

		metrics.setScanStartTime(System.currentTimeMillis());
		logGenerator = new LogGenerator(config);
		detector = new Detector(config);
		detector.addLogListener(logGenerator);

		try {
			String userName = System.getProperty("user.name");
			if (config.isAllDrives()) {
				List<String> allDrives = new ArrayList<String>();
				for (Partition drive : PartitionLoader.getPartitions()) {
					if (isExcluded(drive.getPath()))
						continue;

					if (drive.getType().equals("Network Share"))
						continue;

					if (drive.getName().contains("Google Drive"))
						continue;

					allDrives.add(drive.getPath());
				}

				System.out.println("Scanning drives by user '" + userName + "': " + StringUtils.join(allDrives, ", ")
						+ getExcludeDescription());
				System.out.println("");

				for (String drivePath : allDrives)
					traverse(new File(drivePath), 0);
			} else if (!config.getDriveLetters().isEmpty()) {

				List<String> drives = new ArrayList<String>();
				for (File drive : config.getDriveLetters())
					drives.add(drive.getAbsolutePath());

				System.out.println("Scanning drives by user '" + userName + "': " + StringUtils.join(drives, ", ")
						+ getExcludeDescription());
				System.out.println("");

				for (File drive : config.getDriveLetters())
					traverse(drive, 0);
			} else if (config.getIncludeFilePath() != null) {
				System.out.println(
						"Scanning files by user '" + userName + "' in " + config.getIncludeFilePath() + getExcludeDescription());
				System.out.println("");

				BufferedReader br = null;
				try {
					br = new BufferedReader(new InputStreamReader(new FileInputStream(config.getIncludeFilePath()), "utf-8"));
					while (true) {
						String filePath = br.readLine();
						if (filePath == null)
							break;

						filePath = filePath.trim();

						// skip empty or commented line
						if (filePath.isEmpty() || filePath.startsWith("#"))
							continue;

						traverse(new File(filePath), 0);
					}

				} finally {
					IoUtils.ensureClose(br);
				}

			} else {
				String targetMsg = StringUtils.join(config.getTargetPaths(), ", ");
				System.out.println("Scanning directory by user '" + userName + "': " + targetMsg + getExcludeDescription());

				for (String targetPath : config.getTargetPaths()) {
					File f = new File(targetPath);
					traverse(f, 0);
				}
			}

			if (config.isFix())
				fix();

			try {
				ReportGenerator.writeReportFile(config, metrics, detector);
				ReportGenerator.sendReport(config, metrics, detector);
			} catch (IllegalStateException e) {
				System.out.println(e.getMessage());
			}

		} finally {
			IoUtils.ensureClose(logGenerator);

			long elapsed = System.currentTimeMillis() - metrics.getScanStartTime();
			System.out.println();
			System.out.println(
					"Scanned " + metrics.getScanDirCount() + " directories and " + metrics.getScanFileCount() + " files");
			System.out.println("Found " + detector.getVulnerableFileCount() + " vulnerable files");
			System.out.println("Found " + detector.getPotentiallyVulnerableFileCount() + " potentially vulnerable files");
			System.out.println("Found " + detector.getMitigatedFileCount() + " mitigated files");
			if (config.isFix())
				System.out.println("Fixed " + metrics.getFixedFileCount()
						+ " vulnerable log4j2 files and potentially vulnerable log4j1 files");

			System.out.printf("Completed in %.2f seconds\n", elapsed / 1000.0);
		}

		if (config.isOldExitCode()) {
			return (detector.getVulnerableFileCount() + detector.getPotentiallyVulnerableFileCount());
		} else if (metrics.getErrorCount() > 0) {
			return 2;
		} else if (detector.getVulnerableFileCount() > 0 || detector.getPotentiallyVulnerableFileCount() > 0) {
			return 1;
		} else {
			// vulnerableFileCount == 0 && potentiallyVulnerableFileCount == 0
			return 0;
		}
	}

	protected String getExcludeDescription() {
		String excludeMsg = "";
		if (!config.getExcludePathPrefixes().isEmpty())
			excludeMsg = " (without " + StringUtils.join(config.getExcludePathPrefixes(), ", ") + ")";
		return excludeMsg;
	}

	protected void fix() {
		if (!detector.getVulnerableFiles().isEmpty())
			System.out.println("");

		// collect backup files to zip
		List<File> backupFiles = new ArrayList<File>();

		for (VulnerableFile vf : detector.getVulnerableFiles()) {
			File f = vf.getFile();
			File symlinkFile = null;
			String symlinkMsg = "";

			if (FileUtils.isSymlink(f)) {
				try {
					symlinkFile = f;
					f = symlinkFile.getCanonicalFile();
					symlinkMsg = " (from symlink " + symlinkFile.getAbsolutePath() + ")";
				} catch (IOException e) {
					// unreachable (already known symlink)
				}
			}

			if (config.isTrace())
				System.out.printf("Patching %s%s%n", f.getAbsolutePath(), symlinkMsg);

			File backupFile = new File(f.getAbsolutePath() + ".bak");

			if (backupFile.exists()) {
				reportError(f, "Cannot create backup file. .bak File already exists");
				continue;
			}

			// do not patch if jar has only CVE-2021-45105 or CVE-2021-44832 vulnerability
			Set<String> exceptCves = new HashSet<String>();
			boolean needFix = false;

			// report entries are added by original file. beware of symbolic link case
			List<ReportEntry> entries = detector.getReportEntries(vf.getFile());
			for (ReportEntry entry : entries) {
				String cve = entry.getCve();
				if (cve.equals("CVE-2021-45105") || cve.equals("CVE-2021-44832"))
					exceptCves.add(cve);
				else
					needFix = true;
			}

			String except = "";
			if (!exceptCves.isEmpty())
				except = " (except " + StringUtils.join(exceptCves, ", ") + ")";

			if (!needFix) {
				System.out.printf("Cannot fix " + StringUtils.join(exceptCves, ", ") + ", Upgrade it: %s%s%n",
						f.getAbsolutePath(), symlinkMsg);
				continue;
			}

			boolean readonlyFile = false;
			boolean lockError = true;
			boolean truncateError = true;
			try {
				// set writable if file is read-only
				if (!f.canWrite()) {
					readonlyFile = true;
					if (!f.setWritable(true)) {
						reportError(f, "No write permission. Cannot remove read-only attribute");
						continue;
					}
				}

				// check lock first
				FileUtils.checkLock(f);
				lockError = false;

				FileUtils.copyAsIs(f, backupFile);

				// keep inode as is for symbolic link
				FileUtils.truncate(f);
				truncateError = false;

				Set<String> shadePatterns = detector.getShadePatterns();

				try {
					ZipUtils.repackage(backupFile, f, detector.getDeleteTargetChecker(), shadePatterns, config.isScanZip(),
							vf.isNestedJar(), config.isDebug(), vf.getAltCharset());

					// update fixed status
					for (ReportEntry entry : entries) {
						if (!entry.getCve().equals("CVE-2021-45105"))
							entry.setFixed(true);
					}

					metrics.addFixedFileCount();

					System.out.printf("Fixed: %s%s%s%n", f.getAbsolutePath(), symlinkMsg, except);

					backupFiles.add(backupFile);
				} catch (Throwable t) {
					reportError(f, "Cannot fix file (" + t.getMessage() + ").", t);

					// rollback operation
					FileUtils.copyAsIs(backupFile, f);
				}

			} catch (Throwable t) {
				if (lockError) {
					reportError(f, "Cannot lock file " + t.getMessage(), t);
				} else if (truncateError) {
					if (!backupFile.delete())
						System.out.println("Error: Backup file cannot be deleted - " + backupFile.getAbsolutePath());

					reportError(f, "Cannot truncate file " + t.getMessage(), t);
				} else {
					reportError(f, "Cannot backup file " + t.getMessage(), t);
				}
			} finally {
				// restore read only attribute
				if (readonlyFile) {
					if (!f.setReadOnly())
						System.out.println("Error: File cannot be set as read only - " + f.getAbsolutePath());
				}
			}
		}

		// archive backup files
		if (backupFiles.isEmpty())
			return;

		SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmss");
		String timestamp = df.format(new Date(metrics.getScanStartTime()));
		File f = new File("log4j2_scan_backup_" + timestamp + "." + config.getBackupExtension());
		if (config.getBackupPath() != null)
			f = config.getBackupPath();

		ZipOutputStream zos = null;
		try {
			zos = new ZipOutputStream(new FileOutputStream(f));
			for (File backupFile : backupFiles) {
				String entryPath = backupFile.getAbsolutePath();
				if (isWindows) {
					entryPath = entryPath.replaceAll("\\\\", "/");
					// remove drive colon. e.g. c:/ to c/
					entryPath = entryPath.charAt(0) + entryPath.substring(2);
				}

				entryPath = entryPath.substring(0, entryPath.length() - ".bak".length());

				zos.putNextEntry(new ZipEntry(entryPath));

				FileInputStream is = null;
				try {
					is = new FileInputStream(backupFile);
					FileUtils.transfer(is, zos);
				} finally {
					IoUtils.ensureClose(is);
				}
			}
		} catch (IOException e) {
			throw new IllegalStateException("Cannot archive backup files to " + f.getAbsolutePath(), e);
		} finally {
			IoUtils.ensureClose(zos);
		}

		// delete backup files only if zip file is generated
		for (File backupFile : backupFiles) {
			if (!backupFile.delete())
				System.out.println("Error: Backup file cannot be deleted - " + backupFile.getAbsolutePath());
		}
	}

	protected void traverse(File f, int depth) {
		if (!config.isSilent() && metrics.canStatusReporting())
			printScanStatus();

		String path = f.getAbsolutePath();

		if (depth == 0 && !f.exists()) {
			reportError(f, "File not found");
			return;
		}

		if (f.isDirectory()) {
			metrics.setLastVisitDirectory(f);

			if (isExcluded(path)) {
				if (config.isTrace())
					System.out.println("Skipping excluded directory: " + path);

				return;
			}

			if (depth > 0 && FileUtils.isSymlink(f)) {
				if (config.isTrace())
					System.out.println("Skipping symlink: " + path);

				return;
			}

			if (isExcludedDirectory(path)) {
				if (config.isTrace())
					System.out.println("Skipping directory: " + path);

				return;
			}

			if (config.isTrace())
				System.out.println("Scanning directory: " + path);

			metrics.addScanDirCount();

			DirectoryStream<Path> stream = null;
			Iterator<Path> it = null;
			try {
				stream = Files.newDirectoryStream(f.toPath());
				it = stream.iterator();

				while (it.hasNext()) {
					Path p = it.next();
					traverse(p.toFile(), depth + 1);
				}
			} catch (AccessDeniedException e) {
				reportError(f, "Access denied", e);
			} catch (IOException e) {
				String msg = e.getClass().getSimpleName() + " - " + e.getMessage();
				reportError(f, msg, e);
			} finally {
				IoUtils.ensureClose(stream);
			}
		} else {
			metrics.addScanFileCount();

			if (!config.getExcludeFilePaths().isEmpty() && config.getExcludeFilePaths().contains(path.toLowerCase())) {
				if (config.isTrace())
					System.out.println("Skipping file (excluded file): " + path);
			} else if (config.isNoSymlink() && FileUtils.isSymlink(f)) {
				if (config.isTrace())
					System.out.println("Skipping symlink: " + path);
			} else if (ZipUtils.isScanTarget(path, config.isScanZip())) {
				// skip WinRAR file
				if (isWinRarFile(f)) {
					if (config.isTrace())
						System.out.println("Skipping file (winrar): " + path);

					return;
				}

				if (config.isTrace())
					System.out.println("Scanning file: " + path);

				detector.scanJarFile(f, config.isFix());
			} else {
				if (config.isTrace())
					System.out.println("Skipping file: " + path);
			}
		}
	}

	protected boolean isWinRarFile(File f) {
		try {
			// 0x52617221 is 'RAR!'
			return FileUtils.readMagic(f) == 0x52617221;
		} catch (Throwable t) {
			return false;
		}
	}

	protected void printScanStatus() {
		long now = System.currentTimeMillis();
		int elapsed = (int) ((now - metrics.getScanStartTime()) / 1000);
		System.out.printf("Running scan (%ds): scanned %d directories, %d files, last visit: %s%n", elapsed,
				metrics.getScanDirCount(), metrics.getScanFileCount(), metrics.getLastVisitDirectory().getAbsolutePath());

		metrics.setLastStatusLogging();
	}

	protected boolean isExcludedDirectory(String path) {
		if (isWindows && path.toUpperCase().indexOf("$RECYCLE.BIN") == 3)
			return true;

		return (path.equals("/proc") || path.startsWith("/proc/")) || (path.equals("/sys") || path.startsWith("/sys/"))
				|| (path.equals("/dev") || path.startsWith("/dev/")) || (path.equals("/run") || path.startsWith("/run/"))
				|| (path.equals("/var/run") || path.startsWith("/var/run/"));
	}

	protected boolean isExcluded(String path) {
		if (isWindows)
			path = path.toUpperCase();

		for (String excludePath : config.getExcludePathPrefixes()) {
			if (path.startsWith(excludePath))
				return true;
		}

		for (String excludePattern : config.getExcludePatterns()) {
			if (path.contains(excludePattern))
				return true;
		}

		return false;
	}

	protected void reportError(File f, String msg) {
		reportError(f, msg, null);
	}

	protected void reportError(File f, String msg, Throwable t) {
		metrics.addErrorCount();

		// null if --restore mode
		if (detector != null)
			detector.addErrorReport(f, msg);

		System.out.println("Error: " + msg + ". Skipping " + f.getAbsolutePath());

		if (config.isDebug() && t != null) {
			if (!(t instanceof AccessDeniedException))
				t.printStackTrace();
		}
	}
}
