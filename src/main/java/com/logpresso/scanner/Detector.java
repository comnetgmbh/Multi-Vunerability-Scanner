package com.logpresso.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

import com.logpresso.scanner.utils.DummyInputStream;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipFileIterator;
import com.logpresso.scanner.utils.ZipUtils;

public class Detector {
	private static final String POTENTIALLY_VULNERABLE = "N/A - potentially vulnerable";
	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
	private static final String JNDI_LOOKUP_CLASS_SHADE_PATH = "/log4j/core/lookup/JndiLookup.class";
	private static final String LOG4J_CORE_POM_PROPS = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";

	private static final String LOG4J_12_CORE_POM_PROPS = "META-INF/maven/log4j/log4j/pom.properties";
	private static final String LOG4J_12_JMSAPPENDER = "org/apache/log4j/net/JMSAppender.class";
	private static final String LOG4J_12_JMSAPPENDER_SHADE_PATH = "/log4j/net/JMSAppender.class";

	// CVE-2021-42550 (published at 2021-12-16): vulnerable if version <= 1.2.7
	// logback 1.2.9 moved JNDIUtil.class to core package
	private static final String LOGBACK_CLASSIC_POM_PROPS = "META-INF/maven/ch.qos.logback/logback-classic/pom.properties";
	private static final String LOGBACK_JNDI_CLASS_PATH = "ch/qos/logback/classic/util/JNDIUtil.class";

	private Configuration config;

	// result
	private int vulnerableFileCount = 0;
	private int mitigatedFileCount = 0;
	private int potentiallyVulnerableFileCount = 0;
	private int errorCount = 0;
	private Set<VulnerableFile> vulnerableFiles = new TreeSet<VulnerableFile>();

	// one archive file can be mapped to multiple entries
	private Map<File, List<ReportEntry>> fileReports = new TreeMap<File, List<ReportEntry>>();

	public Detector(Configuration config) {
		this.config = config;
	}

	public Map<File, List<ReportEntry>> getFileReports() {
		return fileReports;
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
		InputStream is = null;

		Charset altCharset = null;
		ZipFileIterator it = null;
		try {
			is = new FileInputStream(jarFile);
			DetectResult result = null;

			try {
				it = openZipFileIterator(jarFile, is);
				result = scanStream(jarFile, it, new ArrayList<String>(), Charset.forName("utf-8"));
			} catch (IllegalArgumentException e) {
				// second try with system encoding or alternative encoding
				altCharset = Charset.defaultCharset();
				if (config.getZipCharset() != null)
					altCharset = config.getZipCharset();

				IoUtils.ensureClose(it);
				IoUtils.ensureClose(is);
				is = new FileInputStream(jarFile);

				it = openZipFileIterator(jarFile, is);
				result = scanStream(jarFile, it, new ArrayList<String>(), altCharset);
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
			System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
		} catch (IllegalArgumentException e) {
			if (e.getMessage().equals("MALFORMED")) {
				System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
			} else {
				System.out.printf("Scan error: '%s' on file: %s%n", e.getMessage(), jarFile);
				errorCount++;

				if (config.isDebug())
					e.printStackTrace();
			}
		} catch (Throwable t) {
			System.out.printf("Scan error: '%s' on file: %s%n", t.getMessage(), jarFile);
			errorCount++;

			if (config.isDebug())
				t.printStackTrace();
		} finally {
			IoUtils.ensureClose(it);
			IoUtils.ensureClose(is);
		}
	}

	private ZipFileIterator openZipFileIterator(File jarFile, InputStream is) throws IOException {
		// Try to avoid 'only DEFLATED entries can have EXT descriptor' error
		// See https://bugs.openjdk.java.net/browse/JDK-8143613
		if (jarFile.getName().endsWith(".zip")) {
			return new ZipFileIterator(jarFile);
		} else {
			return new ZipFileIterator(new ZipInputStream(new DummyInputStream(is)));
		}
	}

	private DetectResult scanStream(File jarFile, ZipFileIterator it, List<String> pathChain, Charset charset)
			throws IOException {
		DetectResult result = new DetectResult();
		String log4j2Version = null;
		String log4j1Version = null;
		String logbackVersion = null;

		boolean log4j2Mitigated = true;

		// log4j1 class
		boolean foundJmsAppender = false;

		// logback class
		boolean foundJndiUtil = false;

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
					log4j2Version = loadVulnerableLog4jVersion(is);

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					log4j2Mitigated = false;

				if (entry.getName().endsWith(JNDI_LOOKUP_CLASS_SHADE_PATH))
					shadedJndiLookupPaths.add(entry.getName());

				if (config.isScanForLog4j1()) {
					if (entry.getName().equals(LOG4J_12_CORE_POM_PROPS))
						log4j1Version = loadVulnerableLog4j1(is);

					if (entry.getName().equals(LOG4J_12_JMSAPPENDER))
						foundJmsAppender = true;

					if (entry.getName().endsWith(LOG4J_12_JMSAPPENDER_SHADE_PATH))
						shadedJmsAppenderPaths.add(entry.getName());
				}

				if (config.isScanForLogback()) {
					if (entry.getName().equals(LOGBACK_CLASSIC_POM_PROPS))
						logbackVersion = loadVulnerableLogback(is);

					if (entry.getName().equals(LOGBACK_JNDI_CLASS_PATH))
						foundJndiUtil = true;
				}

				if (ZipUtils.isScanTarget(entry.getName(), config.isScanZip())) {
					ZipFileIterator nestedIt = null;
					try {
						nestedIt = new ZipFileIterator(new ZipInputStream(new DummyInputStream(is)));
						pathChain.add(entry.getName());

						DetectResult nestedResult = scanStream(jarFile, nestedIt, pathChain, charset);
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

			if (log4j1Version != null) {
				printDetectionForLog4j1(jarFile, pathChain, log4j1Version, !foundJmsAppender);
				if (foundJmsAppender)
					result.setPotentiallyVulnerableLog4j1();
				else
					result.setMitigated();
			} else if (foundJmsAppender) {
				printDetectionForLog4j1(jarFile, pathChain, POTENTIALLY_VULNERABLE, false);
			}

			if (logbackVersion != null) {
				printDetectionForLogback(jarFile, pathChain, logbackVersion, !foundJndiUtil);
				if (foundJndiUtil)
					result.setPotentiallyVulnerableLogback();
				else
					result.setMitigated();
			} else if (foundJndiUtil) {
				printDetectionForLogback(jarFile, pathChain, POTENTIALLY_VULNERABLE, false);
			}

			return result;
		} catch (IOException e) {
			// ignore WinRAR
			if (isWinRarFile(jarFile, pathChain))
				return result;

			throw e;
		}
	}

	private boolean isWinRarFile(File jarFile, List<String> pathChain) {
		String fileName = null;
		if (pathChain.isEmpty())
			fileName = jarFile.getName();
		else
			fileName = pathChain.get(pathChain.size() - 1);

		return fileName.toLowerCase().endsWith(".rar");
	}

	private String loadVulnerableLog4jVersion(InputStream is) throws IOException {
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

	private String loadVulnerableLog4j1(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		return props.getProperty("version");
	}

	private String loadVulnerableLogback(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("ch.qos.logback") && artifactId.equals("logback-classic")) {
			Version v = Version.parse(version);
			if (isVulnerableLogback(v))
				return version;
		}

		return null;
	}

	private boolean isVulnerableLog4j2(Version v) {
		// 2.12.2 has CVE-2021-45105
		return v.getMajor() == 2 && v.getMinor() < 17;
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

		String cve = "CVE-2021-44228";
		if (version.startsWith("2.15."))
			cve = "CVE-2021-45046";
		else if (version.startsWith("2.16.") || version.equals("2.12.2"))
			cve = "CVE-2021-45105";

		msg += " Found " + cve + " (log4j 2.x) vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);
		addReport(jarFile, pathChain, version, mitigated, potential);
	}

	private void printDetectionForLog4j1(File jarFile, List<String> pathChain, String version, boolean mitigated) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";

		String msg = "[?] Found CVE-2021-4104  (log4j 1.2) vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);

		addReport(jarFile, pathChain, version, false, true);
	}

	private void printDetectionForLogback(File jarFile, List<String> pathChain, String version, boolean mitigated) {
		String path = jarFile.getAbsolutePath();
		if (pathChain != null && !pathChain.isEmpty())
			path += " (" + StringUtils.toString(pathChain) + ")";

		String msg = "[?] Found CVE-2021-42550 (logback 1.2.7) vulnerability in " + path + ", logback " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);

		addReport(jarFile, pathChain, version, false, true);
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

		ReportEntry entry = new ReportEntry(jarFile, StringUtils.toString(pathChain), version, status);
		entries.add(entry);
	}
}
