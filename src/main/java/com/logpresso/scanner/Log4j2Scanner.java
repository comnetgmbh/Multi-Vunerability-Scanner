package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.logpresso.scanner.utils.FileUtils;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipUtils;

public class Log4j2Scanner {
	private static final String BANNER = "Logpresso CVE-2021-44228 Vulnerability Scanner 2.3.4 (2021-12-20)";

	private static final boolean isWindows = File.separatorChar == '\\';

	private Configuration config;
	private Metrics metrics;
	private Detector detector;

	public static void main(String[] args) {
		try {
			System.out.println(BANNER);
			Log4j2Scanner scanner = new Log4j2Scanner();
			scanner.run(args);
		} catch (Throwable t) {
			System.out.println("Error: " + t.getMessage());
			t.printStackTrace();
			System.exit(-1);
		}
	}

	public void run(String[] args) throws Exception {
		if (args.length < 1) {
			Configuration.pringUsage();
			return;
		}

		config = Configuration.parseArguments(args);
		metrics = new Metrics();

		if (config.isFix() && !config.isForce()) {
			try {
				if (config.isScanForLog4j1()) {
					System.out.print("This command will remove JndiLookup.class from log4j2-core binaries and "
							+ "remove JMSAppender.class, SocketServer.class, SMTPAppender.class, SMTPAppender$1.class "
							+ "from log4j1-core binaries. Are you sure [y/N]? ");
				} else {
					System.out.print("This command will remove JndiLookup.class from log4j2-core binaries. Are you sure [y/N]? ");
				}
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String answer = br.readLine();
				if (!answer.equalsIgnoreCase("y")) {
					System.out.println("interrupted");
					return;
				}
			} catch (Throwable t) {
				System.out.println("error: " + t.getMessage());
				System.exit(-1);
				return;
			}
		}

		run();

		if (config.isOldExitCode()) {
			System.exit(detector.getVulnerableFileCount() + detector.getPotentiallyVulnerableFileCount());
		} else if (metrics.getErrorCount() > 0) {
			System.exit(2);
		} else if (detector.getVulnerableFileCount() > 0 || detector.getPotentiallyVulnerableFileCount() > 0) {
			System.exit(1);
		} else {
			// vulnerableFileCount == 0 && potentiallyVulnerableFileCount == 0
			System.exit(0);
		}
	}

	public void run() throws IOException {
		metrics.setScanStartTime(System.currentTimeMillis());
		detector = new Detector(config);

		try {
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

				System.out.println("Scanning drives: " + StringUtils.join(allDrives, ", ") + getExcludeDescription());
				System.out.println("");

				for (String drivePath : allDrives)
					traverse(new File(drivePath));
			} else if (!config.getDriveLetters().isEmpty()) {

				List<String> drives = new ArrayList<String>();
				for (File drive : config.getDriveLetters())
					drives.add(drive.getAbsolutePath());

				System.out.println("Scanning drives: " + StringUtils.join(drives, ", ") + getExcludeDescription());
				System.out.println("");

				for (File drive : config.getDriveLetters())
					traverse(drive);
			} else if (config.getIncludeFilePath() != null) {
				System.out.println("Scanning files in " + config.getIncludeFilePath() + getExcludeDescription());
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

						traverse(new File(filePath));
					}

				} finally {
					IoUtils.ensureClose(br);
				}

			} else {
				String targetMsg = StringUtils.join(config.getTargetPaths(), ", ");
				System.out.println("Scanning directory: " + targetMsg + getExcludeDescription());

				for (String targetPath : config.getTargetPaths()) {
					File f = new File(targetPath);
					traverse(f);
				}
			}

			if (config.isFix())
				fix();

			try {
				ReportGenerator.writeReportFile(config, detector.getFileReports(), metrics);
			} catch (IllegalStateException e) {
				System.out.println(e.getMessage());
			}

		} finally {
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
	}

	private String getExcludeDescription() {
		String excludeMsg = "";
		if (!config.getExcludePaths().isEmpty())
			excludeMsg = " (without " + StringUtils.join(config.getExcludePaths(), ", ") + ")";
		return excludeMsg;
	}

	private void fix() {
		if (!detector.getVulnerableFiles().isEmpty())
			System.out.println("");

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
				System.out.println("Error: Cannot create backup file. .bak File already exists. Skipping " + f.getAbsolutePath());
				metrics.addErrorCount();
				continue;
			}

			// check lock first
			if (FileUtils.isLocked(f)) {
				System.out.println("Error: File is locked by other process. Skipping " + f.getAbsolutePath());
				metrics.addErrorCount();
				continue;
			}

			if (FileUtils.copyAsIs(f, backupFile)) {
				// keep inode as is for symbolic link
				if (!FileUtils.truncate(f)) {
					System.out.println("Error: Cannot patch locked file " + f.getAbsolutePath());
					backupFile.delete();
					metrics.addErrorCount();
					continue;
				}

				Set<String> removeTargets = detector.getVulnerableEntries();
				Set<String> shadePatterns = detector.getShadePatterns();

				if (ZipUtils.repackage(backupFile, f, removeTargets, shadePatterns, config.isScanZip(), vf.isNestedJar(),
						config.isDebug(), vf.getAltCharset())) {
					metrics.addFixedFileCount();

					System.out.printf("Fixed: %s%s%n", f.getAbsolutePath(), symlinkMsg);

					// update fixed status
					List<ReportEntry> entries = detector.getReportEntries(f);
					for (ReportEntry entry : entries)
						entry.setFixed(true);
				} else {
					metrics.addErrorCount();

					// rollback operation
					FileUtils.copyAsIs(backupFile, f);
				}
			} else {
				metrics.addErrorCount();
			}
		}
	}

	private void traverse(File f) {
		if (!config.isSilent() && metrics.canStatusReporting())
			printScanStatus();

		String path = f.getAbsolutePath();

		if (f.isDirectory()) {
			metrics.setLastVisitDirectory(f);

			if (isExcluded(path)) {
				if (config.isTrace())
					System.out.println("Skipping excluded directory: " + path);

				return;
			}

			if (FileUtils.isSymlink(f)) {
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

			File[] files = f.listFiles();
			if (files == null)
				return;

			for (File file : files) {
				traverse(file);
			}
		} else {
			metrics.addScanFileCount();

			if (config.isNoSymlink() && FileUtils.isSymlink(f)) {
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

	private boolean isWinRarFile(File f) {
		try {
			// 0x52617221 is 'RAR!'
			return FileUtils.readMagic(f) == 0x52617221;
		} catch (Throwable t) {
			return false;
		}
	}

	private void printScanStatus() {
		long now = System.currentTimeMillis();
		int elapsed = (int) ((now - metrics.getScanStartTime()) / 1000);
		System.out.printf("Running scan (%ds): scanned %d directories, %d files, last visit: %s%n", elapsed,
				metrics.getScanDirCount(), metrics.getScanFileCount(), metrics.getLastVisitDirectory().getAbsolutePath());

		metrics.setLastStatusLogging();
	}

	private boolean isExcludedDirectory(String path) {
		if (isWindows && path.toUpperCase().indexOf("$RECYCLE.BIN") == 3)
			return true;

		return (path.equals("/proc") || path.startsWith("/proc/")) || (path.equals("/sys") || path.startsWith("/sys/"))
				|| (path.equals("/dev") || path.startsWith("/dev/")) || (path.equals("/run") || path.startsWith("/run/"))
				|| (path.equals("/var/run") || path.startsWith("/var/run/"));
	}

	private boolean isExcluded(String path) {
		if (isWindows)
			path = path.toUpperCase();

		for (String excludePath : config.getExcludePaths()) {
			if (path.startsWith(excludePath))
				return true;
		}

		for (String excludePattern : config.getExcludePatterns()) {
			if (path.contains(excludePattern))
				return true;
		}

		return false;
	}
}
