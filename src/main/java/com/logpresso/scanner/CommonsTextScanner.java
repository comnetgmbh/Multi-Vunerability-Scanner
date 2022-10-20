package com.logpresso.scanner;

import com.logpresso.scanner.utils.FileUtils;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipUtils;

import java.io.*;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class CommonsTextScanner extends Log4j2Scanner {

	public int run(Configuration config) throws Exception {
		this.config = config;
		metrics = new Metrics(config.getThrottle());

		if (config.isFix() && !config.isForce()) {
			try {
				System.out.print("This command will remove StringSubstitutor.class from binaries. Are you sure [y/N]? ");

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

	public int scanAndFix() throws IOException {
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
						+ " vulnerable files");

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
		File f = new File("commonstext_scan_backup_" + timestamp + "." + config.getBackupExtension());
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

}
