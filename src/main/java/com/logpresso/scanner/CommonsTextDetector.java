package com.logpresso.scanner;

import com.logpresso.scanner.utils.*;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

import java.io.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

public class CommonsTextDetector extends Detector {
	private static final String POTENTIALLY_VULNERABLE = "N/A";

	private static final String SUBSTITUTRE_CLASS_PATH = "org/apache/commons/text/StringSubstitutor.class";
	private static final String SUBSTITUTRE_CLASS_SHADE_PATH = "/commons/text/StringSubstitutor.class";
	private static final String APACHECOMMONS_CORE_POM_PROPS = "META-INF/maven/org.apache.commons/commons-text/pom.properties";

	private Configuration config;

	// result
	private int vulnerableFileCount = 0;
	private int mitigatedFileCount = 0;
	private int potentiallyVulnerableFileCount = 0;
	private int errorCount = 0;
	private Set<VulnerableFile> vulnerableFiles = new TreeSet<VulnerableFile>();

	// one archive file can be mapped to multiple entries
	private Map<File, List<ReportEntry>> fileReports = new TreeMap<File, List<ReportEntry>>();
	private List<ReportEntry> errorReports = new LinkedList<ReportEntry>();

	private Set<LogListener> logListeners = new CopyOnWriteArraySet<LogListener>();

	public CommonsTextDetector(Configuration config) {
		super(config);
		this.config = config;
	}

	public void addLogListener(LogListener listener) {
		this.logListeners.add(listener);
	}

	public void removeLogListener(LogListener listener) {
		this.logListeners.remove(listener);
	}

	public Map<File, List<ReportEntry>> getFileReports() {
		return fileReports;
	}

	public List<ReportEntry> getErrorReports() {
		return errorReports;
	}

	public DeleteTargetChecker getDeleteTargetChecker() {
		return new CommonsTextDeleteTargetChecker();
	}

	public Set<String> getVulnerableEntries() {
		Set<String> targets = new HashSet<String>();
		targets.add(SUBSTITUTRE_CLASS_PATH);
		return targets;
	}

	public Set<String> getShadePatterns() {
		Set<String> targets = new HashSet<String>();
		for (String fqdn : getVulnerableEntries()) {
			int p = fqdn.indexOf("/commons/text");
			if (p > 0)
				targets.add(fqdn.substring(p));
		}

		return targets;
	}

	public int getVulnerableFileCount() {
		return vulnerableFileCount;
	}

	public int getMitigatedFileCount() {
		return mitigatedFileCount;
	}

	public int getPotentiallyVulnerableFileCount() {
		return potentiallyVulnerableFileCount;
	}

	public int getErrorCount() {
		return errorCount;
	}

	public Set<VulnerableFile> getVulnerableFiles() {
		return vulnerableFiles;
	}

	public List<ReportEntry> getReportEntries(File f) {
		return fileReports.get(f);
	}

	protected void scanJarFile(File jarFile, boolean fix) {
		scanJarFile(jarFile, fix, Charset.forName("utf-8"));
	}

	protected void scanJarFile(File jarFile, boolean fix, Charset charset) {
		InputStream is = null;

		Charset altCharset = null;
		ZipFileIterator it = null;
		try {
			is = new BufferedInputStream(new FileInputStream(jarFile));
			DetectResult result = null;

			try {
				it = openZipFileIterator(jarFile, is, charset, 0);
				result = scanStream(jarFile, it, new ArrayList<String>(), Charset.forName("utf-8"), 0);
			} catch (IllegalArgumentException e) {
				// second try with system encoding or alternative encoding
				altCharset = Charset.defaultCharset();
				if (config.getZipCharset() != null)
					altCharset = config.getZipCharset();

				IoUtils.ensureClose(it);
				IoUtils.ensureClose(is);
				is = new BufferedInputStream(new FileInputStream(jarFile));

				it = openZipFileIterator(jarFile, is, charset, 0);
				result = scanStream(jarFile, it, new ArrayList<String>(), altCharset, 0);
			}

			if (result.isVulnerable())
				vulnerableFileCount++;
			else if (result.isMitigated())
				mitigatedFileCount++;
			else if (result.isPotentiallyVulnerable())
				potentiallyVulnerableFileCount++;

			if (fix && result.isFixRequired())
				vulnerableFiles.add(new VulnerableFile(jarFile, result.hasNestedJar(), altCharset));

		} catch (ZipException e) {
			// ignore broken zip file
			reportError(jarFile, String.format("Skipping broken jar file %s ('%s')", jarFile, e.getMessage()));
		} catch (IllegalArgumentException e) {
			if (e.getMessage().equals("MALFORMED")) {
				reportError(jarFile, String.format("Skipping broken jar file %s ('%s')", jarFile, e.getMessage()));
			} else {
				reportError(jarFile, String.format("Scan error: '%s' on file: %s", e.getMessage(), jarFile));

				if (config.isDebug())
					e.printStackTrace();
			}
		} catch (Throwable t) {
			reportError(jarFile, String.format("Scan error: '%s' on file: %s", t.getMessage(), jarFile));

			if (config.isDebug())
				t.printStackTrace();
		} finally {
			IoUtils.ensureClose(it);
			IoUtils.ensureClose(is);
		}
	}

	private ZipFileIterator openZipFileIterator(File jarFile, InputStream is, Charset charset, int depth) throws IOException {
		// Try to avoid 'only DEFLATED entries can have EXT descriptor' error
		// See https://bugs.openjdk.java.net/browse/JDK-8143613
		try {
			return new ZipFileIterator(new ZipArchiveInputStream(new DummyInputStream(is)));
		} catch (Exception e) {
			if (depth == 0)
				return new ZipFileIterator(jarFile, charset);

			return new ZipFileIterator(new ZipInputStream(new DummyInputStream(is), charset));
		}
	}

	private CommonsTextDetectResult scanStream(File jarFile, ZipFileIterator it, List<String> pathChain, Charset charset, int depth)
			throws IOException {
		CommonsTextDetectResult result = new CommonsTextDetectResult();
		String commonsTextVersion = null;

		boolean commonsTextMitigated = true;

		// shade class
		Set<String> shadedLookupPaths = new TreeSet<String>();

		// for commons-text md5 detection
		List<String> md5Targets = CommonsTextVersionClassifier.getCommonsTextMd5Entries();
		Map<String, String> md5Map = new HashMap<String, String>();

		try {
			while (true) {
				ZipEntry entry = it.getNextEntry();
				if (entry == null)
					break;

				InputStream is = it.getNextInputStream();

				String md5EntryName = getMd5EntryName(md5Targets, entry.getName());
				if (md5EntryName != null)
					md5Map.put(md5EntryName, VersionClassifier.md5(is));

				if (entry.getName().equals(APACHECOMMONS_CORE_POM_PROPS))
					commonsTextVersion = loadCommonsTextVersion(is);

				if (entry.getName().equals(SUBSTITUTRE_CLASS_PATH))
					commonsTextMitigated = false;

				if (entry.getName().endsWith(SUBSTITUTRE_CLASS_SHADE_PATH))
					shadedLookupPaths.add(entry.getName());

				if (ZipUtils.isScanTarget(entry.getName(), config.isScanZip())) {
					ZipFileIterator nestedIt = null;
					try {
						nestedIt = openZipFileIterator(jarFile, is, charset, depth + 1);
						pathChain.add(entry.getName());

						CommonsTextDetectResult nestedResult = scanStream(jarFile, nestedIt, pathChain, charset, depth + 1);
						result.merge(nestedResult);

						pathChain.remove(pathChain.size() - 1);
					} finally {
						IoUtils.ensureClose(nestedIt);
					}
				}
			}

			commonsTextMitigated &= shadedLookupPaths.isEmpty();

			if (commonsTextVersion == null)
				commonsTextVersion = CommonsTextVersionClassifier.classifyCommonsTextVersion(md5Map);

			if (commonsTextVersion != null) {
				if (isVulnerableCommonsText(Version.parse(commonsTextVersion))) {
					printDetectionForCommonsText(jarFile, pathChain, commonsTextVersion, commonsTextMitigated, false);
					if (commonsTextMitigated)
						result.setMitigated();
					else
						result.setVulnerable();
				} else {
					printSafeCommonsText(jarFile, pathChain, commonsTextVersion);
				}
			} else if (!commonsTextMitigated) {
				printDetectionForCommonsText(jarFile, pathChain, POTENTIALLY_VULNERABLE, false, true);
				result.setPotentiallyVulnerable();
			}

			return result;
		} catch (

		IOException e) {
			// ignore WinRAR
			if (isWinRarFile(jarFile, pathChain))
				return result;

			throw e;
		}
	}

	private String getMd5EntryName(List<String> md5Targets, String entryName) {
		for (String s : md5Targets) {
			if (entryName.endsWith(s)) {
				int p = entryName.lastIndexOf('/');
				if (p > 0)
					return entryName.substring(p + 1);
			}
		}

		return null;
	}

	private boolean isWinRarFile(File jarFile, List<String> pathChain) {
		String fileName = null;
		if (pathChain.isEmpty())
			fileName = jarFile.getName();
		else
			fileName = pathChain.get(pathChain.size() - 1);

		return fileName.toLowerCase().endsWith(".rar");
	}

	private String loadCommonsTextVersion(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("org.apache.commons") && artifactId.equals("commons-text")) {
			return version;
		}
		return null;
	}

	private boolean isVulnerableCommonsText(Version v) {
		if (v.getMajor() == 1 && v.getMinor() > 9)
			return false;

		if (v.getMajor() == 1 && v.getMinor() < 5)
			return false;

		return true;
	}

	private void printDetectionForCommonsText(File jarFile, List<String> pathChain, String version, boolean mitigated,
											  boolean potential) {
		String path = getPath(jarFile, pathChain);

		String msg = potential ? "[?]" : "[*]";

		Version v = null;
		if (!version.equals("N/A"))
			v = Version.parse(version);

		// sort desc by cvss
		String cve = "CVE-2022-42889";

		msg += " Found " + cve + " vulnerability in " + path + ", commons-text " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);
		addReport(jarFile, pathChain, "commons-text", version, cve, mitigated, potential);
	}

	private void printSafeCommonsText(File jarFile, List<String> pathChain, String version) {
		if (config.isReportPatch()) {
			String path = getPath(jarFile, pathChain);
			System.out.println("[-] Found safe commons-text " + version + " version in " + path);
			addSafeReport(jarFile, pathChain, "commons-text", version);
		}
	}

	private String getPath(File jarFile, List<String> pathChain) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";
		return path;
	}

	public void addErrorReport(File jarFile, String error) {
		errorCount++;

		ReportEntry entry = new ReportEntry(jarFile, error);

		// heap guard for error exploding
		if (errorReports.size() < 100000)
			errorReports.add(entry);

		// invoke listeners
		for (LogListener listener : logListeners) {
			try {
				listener.onError(entry);
			} catch (Throwable t) {
				// listener should not throw any exception
				if (config.isDebug())
					t.printStackTrace();
			}
		}
	}

	private void addReport(File jarFile, List<String> pathChain, String product, String version, String cve, boolean mitigated,
			boolean potential) {
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

		ReportEntry entry = new ReportEntry(jarFile, StringUtils.toString(pathChain), product, version, cve, status);
		entries.add(entry);

		// invoke listeners
		for (LogListener listener : logListeners) {
			try {
				listener.onDetect(entry);
			} catch (Throwable t) {
				// listener should not throw any exception
				if (config.isDebug())
					t.printStackTrace();
			}
		}
	}

	private void reportError(File jarFile, String msg) {
		System.out.println(msg);
		addErrorReport(jarFile, msg);
	}

	private void addSafeReport(File jarFile, List<String> pathChain, String product, String version) {
		List<ReportEntry> entries = fileReports.get(jarFile);
		if (entries == null) {
			entries = new ArrayList<ReportEntry>();
			fileReports.put(jarFile, entries);
		}
		ReportEntry entry = new ReportEntry(jarFile, StringUtils.toString(pathChain), product, version);
		entries.add(entry);
	}
}
