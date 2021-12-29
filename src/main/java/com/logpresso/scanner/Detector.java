package com.logpresso.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

import com.logpresso.scanner.utils.DummyInputStream;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipFileIterator;
import com.logpresso.scanner.utils.ZipUtils;

public class Detector {
	private static final String POTENTIALLY_VULNERABLE = "N/A";

	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
	private static final String JNDI_LOOKUP_CLASS_SHADE_PATH = "/log4j/core/lookup/JndiLookup.class";
	private static final String LOG4J_CORE_POM_PROPS = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";

	private static final String LOG4J_12_CORE_POM_PROPS = "META-INF/maven/log4j/log4j/pom.properties";
	private static final String LOG4J_12_JMSAPPENDER = "org/apache/log4j/net/JMSAppender.class";
	private static final String LOG4J_12_JMSAPPENDER_SHADE_PATH = "/log4j/net/JMSAppender.class";
	private static final String LOG4J_12_JMSSINK = "org/apache/log4j/net/JMSSink.class";
	private static final String LOG4J_12_JMSSINK_SHADE_PATH = "/log4j/net/JMSSink.class";

	// CVE-2021-42550 (published at 2021-12-16): vulnerable if version <= 1.2.7
	// logback 1.2.9 moved JNDIUtil.class to core package
	private static final String LOGBACK_CLASSIC_POM_PROPS = "META-INF/maven/ch.qos.logback/logback-classic/pom.properties";
	private static final String LOGBACK_JNDI_CLASS_PATH = "ch/qos/logback/classic/util/JNDIUtil.class";
	private static final String LOGBACK_ENV_CLASS_PATH = "ch/qos/logback/classic/util/EnvUtil.class";

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

	public Detector(Configuration config) {
		this.config = config;
	}

	public Map<File, List<ReportEntry>> getFileReports() {
		return fileReports;
	}

	public List<ReportEntry> getErrorReports() {
		return errorReports;
	}

	public Set<String> getVulnerableEntries() {
		Set<String> targets = new HashSet<String>();
		if (config.isScanForLog4j1()) {
			for (String name : Arrays.asList("SocketServer.class", "JMSAppender.class", "SMTPAppender$1.class",
					"SMTPAppender.class"))
				targets.add("org/apache/log4j/net/" + name);
		}

		targets.add(JNDI_LOOKUP_CLASS_PATH);
		return targets;
	}

	public Set<String> getShadePatterns() {
		Set<String> targets = new HashSet<String>();
		for (String fqdn : getVulnerableEntries()) {
			int p = fqdn.indexOf("/log4j");
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
			is = new FileInputStream(jarFile);
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
				is = new FileInputStream(jarFile);

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

	private DetectResult scanStream(File jarFile, ZipFileIterator it, List<String> pathChain, Charset charset, int depth)
			throws IOException {
		DetectResult result = new DetectResult();
		String log4j2Version = null;
		String log4j1Version = null;
		String logbackVersion = null;

		boolean log4j2Mitigated = true;

		// log4j1 class
		boolean foundJmsAppender = false;
		boolean foundJmsSink = false;

		// logback class
		boolean foundJndiUtil = false;
		boolean foundEnvUtil = false;

		// shade class
		Set<String> shadedJndiLookupPaths = new TreeSet<String>();
		Set<String> shadedJmsAppenderPaths = new TreeSet<String>();

		try {
			while (true) {
				ZipEntry entry = it.getNextEntry();
				if (entry == null)
					break;

				InputStream is = it.getNextInputStream();
				if (entry.getName().equals(LOG4J_CORE_POM_PROPS))
					log4j2Version = loadLog4j2Version(is);

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					log4j2Mitigated = false;

				if (entry.getName().endsWith(JNDI_LOOKUP_CLASS_SHADE_PATH))
					shadedJndiLookupPaths.add(entry.getName());

				if (config.isScanForLog4j1()) {
					if (entry.getName().equals(LOG4J_12_CORE_POM_PROPS))
						log4j1Version = loadLog4j1Version(is);

					if (entry.getName().equals(LOG4J_12_JMSAPPENDER))
						foundJmsAppender = true;

					if (entry.getName().equals(LOG4J_12_JMSSINK))
						foundJmsSink = true;

					if (entry.getName().endsWith(LOG4J_12_JMSAPPENDER_SHADE_PATH))
						shadedJmsAppenderPaths.add(entry.getName());

					if (entry.getName().endsWith(LOG4J_12_JMSSINK_SHADE_PATH))
						foundJmsSink = true;
				}

				if (config.isScanForLogback()) {
					if (entry.getName().equals(LOGBACK_CLASSIC_POM_PROPS))
						logbackVersion = loadLogbackVersion(is);

					if (entry.getName().equals(LOGBACK_JNDI_CLASS_PATH))
						foundJndiUtil = true;

					if (entry.getName().equals(LOGBACK_ENV_CLASS_PATH))
						foundEnvUtil = true;
				}

				if (ZipUtils.isScanTarget(entry.getName(), config.isScanZip())) {
					ZipFileIterator nestedIt = null;
					try {
						nestedIt = openZipFileIterator(jarFile, is, charset, depth + 1);
						pathChain.add(entry.getName());

						DetectResult nestedResult = scanStream(jarFile, nestedIt, pathChain, charset, depth + 1);
						result.merge(nestedResult);

						pathChain.remove(pathChain.size() - 1);
					} finally {
						IoUtils.ensureClose(nestedIt);
					}
				}
			}

			log4j2Mitigated &= shadedJndiLookupPaths.isEmpty();
			if (log4j2Version != null) {
				if (isVulnerableLog4j2(Version.parse(log4j2Version))) {
					printDetectionForLog4j2(jarFile, pathChain, log4j2Version, log4j2Mitigated, false);
					if (log4j2Mitigated)
						result.setMitigated();
					else
						result.setVulnerable();
				}
			} else if (!log4j2Mitigated) {
				printDetectionForLog4j2(jarFile, pathChain, POTENTIALLY_VULNERABLE, false, true);
				result.setPotentiallyVulnerableLog4j2();
			}

			boolean log4j1Found = log4j1Version != null || foundJmsAppender || foundJmsSink;
			boolean log4j1Mitigated = !foundJmsAppender;
			log4j1Mitigated &= shadedJmsAppenderPaths.isEmpty();

			if (log4j1Found) {
				if (log4j1Version != null)
					printDetectionForLog4j1(jarFile, pathChain, log4j1Version, log4j1Mitigated);
				else
					printDetectionForLog4j1(jarFile, pathChain, POTENTIALLY_VULNERABLE, log4j1Mitigated);

				if (log4j1Mitigated)
					result.setMitigated();
				else
					result.setPotentiallyVulnerableLog4j1();
			}

			boolean logbackFound = isVulnerableLogback(logbackVersion, foundJndiUtil, foundEnvUtil);
			boolean logbackMitigated = !foundJndiUtil;

			if (logbackFound) {
				if (logbackVersion != null) {
					printDetectionForLogback(jarFile, pathChain, logbackVersion, logbackMitigated);
				} else {
					printDetectionForLogback(jarFile, pathChain, POTENTIALLY_VULNERABLE, logbackMitigated);
				}

				if (logbackMitigated)
					result.setMitigated();
				else
					result.setPotentiallyVulnerableLogback();
			}

			return result;
		} catch (IOException e) {
			// ignore WinRAR
			if (isWinRarFile(jarFile, pathChain))
				return result;

			throw e;
		}
	}

	private boolean isVulnerableLogback(String logbackVersion, boolean foundJndiUtil, boolean foundEnvUtil) {
		boolean logbackFound = false;
		if (logbackVersion != null) {
			if (isVulnerableLogback(Version.parse(logbackVersion)))
				logbackFound = true;
		} else {
			logbackFound = foundJndiUtil || foundEnvUtil;
		}
		return logbackFound;
	}

	private boolean isWinRarFile(File jarFile, List<String> pathChain) {
		String fileName = null;
		if (pathChain.isEmpty())
			fileName = jarFile.getName();
		else
			fileName = pathChain.get(pathChain.size() - 1);

		return fileName.toLowerCase().endsWith(".rar");
	}

	private String loadLog4j2Version(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("org.apache.logging.log4j") && artifactId.equals("log4j-core")) {
			return version;
		}
		return null;
	}

	private String loadLog4j1Version(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);
		return props.getProperty("version");
	}

	private String loadLogbackVersion(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("ch.qos.logback") && artifactId.equals("logback-classic"))
			return version;

		return null;
	}

	private boolean isVulnerableLog4j2(Version v) {
		// according to 2021-12-29 CVE-2021-44832 update
		// Upgrade to Log4j 2.12.4 for Java 7
		if (v.getMajor() == 2 && v.getMinor() == 12 && v.getPatch() >= 4)
			return false;

		// Upgrade to Log4j 2.3.2 for Java 6
		if (v.getMajor() == 2 && v.getMinor() == 3 && v.getPatch() >= 2)
			return false;

		// 2.17.0 has CVE-2021-44832
		return (v.getMajor() == 2 && v.getMinor() < 17) || (v.getMajor() == 2 && v.getMinor() == 17 && v.getPatch() < 1);
	}

	private boolean isVulnerableLogback(Version v) {
		return (v.getMajor() == 1 && v.getMinor() == 2 && v.getPatch() <= 7) || (v.getMajor() == 1 && v.getMinor() <= 1)
				|| (v.getMajor() == 0 && v.getMinor() >= 9);
	}

	private void printDetectionForLog4j2(File jarFile, List<String> pathChain, String version, boolean mitigated,
			boolean potential) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";

		String msg = potential ? "[?]" : "[*]";

		Version v = null;
		if (!version.equals("N/A"))
			v = Version.parse(version);

		// sort desc by cvss
		String cve = "CVE-2021-44228";
		if (v != null) {
			if (v.getMinor() == 15)
				cve = "CVE-2021-45046";
			else if (version.startsWith("2.16.") || version.equals("2.12.2"))
				cve = "CVE-2021-45105";
			else if ((v.getMinor() == 17 && v.getPatch() == 0) || (v.getMinor() == 12 && v.getPatch() == 3)
					|| (v.getMinor() == 3 && v.getPatch() == 1))
				cve = "CVE-2021-44832";
		}

		msg += " Found " + cve + " (log4j 2.x) vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);
		addReport(jarFile, pathChain, "Log4j 2", version, cve, mitigated, potential);
	}

	private void printDetectionForLog4j1(File jarFile, List<String> pathChain, String version, boolean mitigated) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";

		String msg = "[?] Found CVE-2021-4104  (log4j 1.2) vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);

		addReport(jarFile, pathChain, "Log4j 1", version, "CVE-2021-4104", mitigated, true);
	}

	private void printDetectionForLogback(File jarFile, List<String> pathChain, String version, boolean mitigated) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";

		String msg = "[?] Found CVE-2021-42550 (logback 1.2.7) vulnerability in " + path + ", logback " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);

		addReport(jarFile, pathChain, "Logback", version, "CVE-2021-42550", mitigated, true);
	}

	public void addErrorReport(File jarFile, String error) {
		errorCount++;

		// heap guard for error exploding
		if (errorReports.size() < 100000)
			errorReports.add(new ReportEntry(jarFile, error));
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
	}

	private void reportError(File jarFile, String msg) {
		System.out.println(msg);
		addErrorReport(jarFile, msg);
	}

}
