package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.logpresso.scanner.json.JsonArray;
import com.logpresso.scanner.json.JsonObject;
import com.logpresso.scanner.utils.IoUtils;

public class ReportGenerator {

	public static void writeReportFile(Configuration config, Metrics metrics, Detector detector) {
		Map<File, List<ReportEntry>> fileReports = detector.getFileReports();

		if (config.getUdpSyslogAddr() != null)
			sendSyslogs(config, fileReports);

		if (!config.isReportCsv() && !config.isReportJson())
			return;

		if (config.isNoEmptyReport() && fileReports.isEmpty())
			return;

		if (config.isReportCsv()) {
			File f = generateReportFileName(config, metrics, ".csv");
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

		if (config.isReportJson()) {
			File f = generateReportFileName(config, metrics, ".json");
			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(f);
				writeJsonReport(config, detector, fos, metrics);
			} catch (IOException e) {
				throw new IllegalStateException("cannot open json report file: " + e.getMessage(), e);
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
	}

	private static void sendSyslogs(Configuration config, Map<File, List<ReportEntry>> fileReports) {
		DatagramSocket socket = null;
		try {
			socket = new DatagramSocket();
			String critical = "<129>";
			String warn = "<132>";

			String hostname = getHostname(config.isDebug());
			for (File file : fileReports.keySet()) {
				for (ReportEntry entry : fileReports.get(file)) {
					String syslog = entry.getJsonLine(hostname);
					if (entry.getStatus() == Status.VULNERABLE)
						syslog = critical + syslog;
					else if (entry.getStatus() == Status.POTENTIALLY_VULNERABLE)
						syslog = warn + syslog;
					else
						continue;

					byte[] b = syslog.getBytes("utf-8");
					DatagramPacket pkt = new DatagramPacket(b, b.length);
					pkt.setSocketAddress(config.getUdpSyslogAddr());
					socket.send(pkt);
				}
			}
		} catch (IOException e) {
			System.out.println("Error: Cannot send syslog to " + config.getUdpSyslogAddr() + " - " + e.getMessage());
			if (config.isDebug())
				e.printStackTrace();
		} finally {
			IoUtils.ensureClose(socket);
		}

	}

	private static File generateReportFileName(Configuration config, Metrics metrics, String ext) {
		SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmss");

		File f = new File("log4j2_scan_report_" + df.format(new Date(metrics.getScanStartTime())) + ext);
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

	private static void writeJsonReport(Configuration config, Detector detector, FileOutputStream fileOutputStream,
			Metrics metrics) throws IOException {

		// elapsed time in seconds
		long elapsedTime = (System.currentTimeMillis() - metrics.getScanStartTime()) / 1000;

		JsonObject root = new JsonObject();
		JsonArray files = new JsonArray();
		JsonArray errors = null;

		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");

		Map<File, List<ReportEntry>> fileReports = detector.getFileReports();
		for (File file : fileReports.keySet()) {
			JsonArray reports = new JsonArray();

			boolean vulnerable = false;
			boolean potentiallyVulnerable = false;
			boolean mitigated = false;
			for (ReportEntry entry : fileReports.get(file)) {
				vulnerable |= (entry.getStatus() == Status.VULNERABLE);
				potentiallyVulnerable |= (entry.getStatus() == Status.POTENTIALLY_VULNERABLE);
				mitigated |= (entry.getStatus() == Status.MITIGATED);

				JsonObject report = new JsonObject();
				report.put("entry", entry.getEntry());
				report.put("product", entry.getProduct());
				report.put("version", entry.getVersion());
				report.put("cve", entry.getCve());
				report.put("status", entry.getStatus().toString());
				report.put("fixed", entry.isFixed());
				report.put("detected_at", df.format(entry.getReportTime()));
				reports.add(report);
			}

			Status status = Status.NOT_VULNERABLE;
			if (vulnerable)
				status = Status.VULNERABLE;
			else if (potentiallyVulnerable)
				status = Status.POTENTIALLY_VULNERABLE;
			else if (mitigated)
				status = Status.MITIGATED;

			JsonObject fileObj = new JsonObject();
			fileObj.put("path", file.getAbsolutePath());
			fileObj.put("status", status.toString());
			fileObj.put("reports", reports);

			files.add(fileObj);
		}

		if (!detector.getErrorReports().isEmpty()) {
			errors = new JsonArray();
			for (ReportEntry entry : detector.getErrorReports()) {
				JsonObject error = new JsonObject();
				error.put("path", entry.getPath().getAbsolutePath());
				error.put("error", entry.getError());
				error.put("created_at", df.format(entry.getReportTime()));
				errors.add(error);
			}
		}

		String hostname = getHostname(config.isDebug());

		JsonObject summary = new JsonObject();
		summary.put("scanner_banner", Log4j2Scanner.BANNER);
		summary.put("scanner_version", Log4j2Scanner.VERSION);
		summary.put("scanner_release_date", Log4j2Scanner.RELEASE_DATE);
		summary.put("hostname", hostname);
		summary.put("elapsed_time", elapsedTime);
		summary.put("scan_start_time", df.format(new Date(metrics.getScanStartTime())));
		summary.put("scan_end_time", df.format(new Date()));
		summary.put("scan_dir_count", metrics.getScanDirCount());
		summary.put("scan_file_count", metrics.getScanFileCount());
		summary.put("vulnerable_file_count", detector.getVulnerableFileCount());
		summary.put("potentially_vulnerable_file_count", detector.getPotentiallyVulnerableFileCount());
		summary.put("mitigated_file_count", detector.getMitigatedFileCount());
		summary.put("fixed_file_count", metrics.getFixedFileCount());
		summary.put("error_file_count", metrics.getErrorCount() + detector.getErrorCount());

		root.put("summary", summary);

		if (!fileReports.isEmpty())
			root.put("files", files);

		if (errors != null)
			root.put("errors", errors);

		Writer writer = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8);
		try {
			root.write(writer);
		} finally {
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
