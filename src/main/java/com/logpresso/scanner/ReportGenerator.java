package com.logpresso.scanner;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.logpresso.scanner.json.JsonArray;
import com.logpresso.scanner.json.JsonObject;
import com.logpresso.scanner.utils.IoUtils;

public class ReportGenerator {

	public static void writeReportFile(Configuration config, Map<File, List<ReportEntry>> fileReports, Metrics metrics) {
		if (!config.isReportCsv() && !config.isReportJson())
			return;

		if (config.isNoEmptyReport() && fileReports.isEmpty())
			return;

		if(config.isReportCsv()) {
			File f = generateReportFileName(config, ".csv");
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(f);
				writeCsvReport(config, fileReports, fos);
			} catch (IOException e) {
				throw new IllegalStateException("cannot open csv report file: " + e.getMessage(), e);
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
		if(config.isReportJson()) {
			File f = generateReportFileName(config, ".json");
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(f);
				writeJsonReport(config, fileReports, fos, metrics);
			} catch (IOException e) {
				throw new IllegalStateException("cannot open csv report file: " + e.getMessage(), e);
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
	}

	private static File generateReportFileName(Configuration config, String ext) {
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmss");

		File f = new File("log4j2_scan_report_" + df.format(new Date()) + ext);
		if (config.getReportPath() != null) {
			f = new File(config.getReportPath());

			// double check
			if (f.exists())
				throw new IllegalStateException("Cannot write report file. File already exists: " + f.getAbsolutePath());
		} else if (config.getReportDir() != null) {
			f = new File(config.getReportDir(), f.getName());

			// double check
			if (f.exists())
				throw new IllegalStateException("Cannot write report file. File already exists: " + f.getAbsolutePath());
		}

		return f;
	}

	private static void writeCsvReport(Configuration config, Map<File, List<ReportEntry>> fileReports, FileOutputStream csvStream)
			throws IOException, UnsupportedEncodingException {
		String header = String.format("Hostname,Path,Entry,Product,Version,CVE,Status,Fixed,Detected at%n");
		csvStream.write(header.getBytes("utf-8"));

		String hostname = getHostname(config.isDebug());
		if (hostname == null)
			hostname = "";

		for (File file : fileReports.keySet()) {
			for (ReportEntry entry : fileReports.get(file)) {
				String line = entry.getCsvLine();
				line = hostname + "," + line;
				csvStream.write(line.getBytes("utf-8"));
			}
		}
	}

	private static void writeJsonReport(Configuration config, Map<File, List<ReportEntry>> fileReports, FileOutputStream fileOutputStream, Metrics metrics) throws IOException {
		JsonObject root = new JsonObject();
		JsonArray reports = new JsonArray();

		JsonObject metricsObject = new JsonObject();
		metricsObject.put("scanDirCount", metrics.getScanDirCount());
		metricsObject.put("scanFileCount", metrics.getScanFileCount());
		metricsObject.put("scanStartTime", metrics.getScanStartTime());
		metricsObject.put("statusReporting", metrics.canStatusReporting());
		metricsObject.put("errorCount", metrics.getErrorCount());
		metricsObject.put("fixedFileCount", metrics.getFixedFileCount());
		metricsObject.put("lastVisitDirectory", metrics.getLastVisitDirectory().getAbsolutePath());
		metricsObject.put("lastStatusLoggingCount", metrics.getLastStatusLoggingCount());
		metricsObject.put("lastStatusLoggingTime", metrics.getLastStatusLoggingTime());
		root.put("metrics", metricsObject);

		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String hostname = getHostname(config.isDebug());
		for (File file : fileReports.keySet()) {
			for (ReportEntry entry : fileReports.get(file)) {
				JsonObject report = new JsonObject();
				report.put("path", entry.getPath().getAbsolutePath());
				report.put("entry", entry.getEntry());
				report.put("product", entry.getProduct());
				report.put("version", entry.getVersion());
				report.put("cve", entry.getCve());
				report.put("fixed", entry.isFixed());
				report.put("detectedAt", df.format(entry.getReportTime()));
				if(hostname != null) {
					report.put("hostname", hostname);
				}
				reports.put(report);
			}
		}
		root.put("files", reports);
		Writer writer = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8);
		try {
			root.write(writer);
		}
		finally {
			IoUtils.ensureClose(writer);
		}
	}

	private static String getHostname(boolean debug) {
		// Try to fetch hostname without DNS resolving for closed network
		boolean isWindows = File.separatorChar == '\\';
		if (isWindows) {
			return System.getenv("COMPUTERNAME");
		} else {
			Process p = null;
			try {
				p = Runtime.getRuntime().exec("uname -n");
				BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));

				String line = br.readLine();
				return (line == null) ? null : line.trim();
			} catch (IOException e) {
				if (debug)
					e.printStackTrace();

				return null;
			} finally {
				if (p != null)
					p.destroy();
			}
		}
	}
}
