package com.logpresso.scanner;

public class CommonsTextDetectResult extends DetectResult {
	private boolean vulnerable = false;
	private boolean mitigated = false;
	private boolean potentiallyVulnerable = false;
	private boolean nestedJar = false;

	public void merge(CommonsTextDetectResult result) {
		vulnerable |= result.isVulnerable();
		mitigated |= result.isMitigated();
		potentiallyVulnerable |= result.isPotentiallyVulnerable();
		nestedJar = true;
	}

	public boolean isVulnerable() {
		return vulnerable;
	}

	public void setVulnerable() {
		this.vulnerable = true;
	}

	public boolean isMitigated() {
		return mitigated;
	}

	public void setMitigated() {
		this.mitigated = true;
	}

	public void setPotentiallyVulnerable() {
		this.potentiallyVulnerable = true;
	}

	public boolean hasNestedJar() {
		return nestedJar;
	}

	public void setNestedJar(boolean nestedJar) {
		this.nestedJar |= nestedJar;
	}

	public Status getStatus() {
		if (vulnerable)
			return Status.VULNERABLE;
		else if (mitigated)
			return Status.MITIGATED;
		else if (isPotentiallyVulnerable())
			return Status.POTENTIALLY_VULNERABLE;
		return Status.NOT_VULNERABLE;
	}

	public boolean isPotentiallyVulnerable() {
		return potentiallyVulnerable;
	}

	public boolean isFixRequired() {
		return vulnerable || potentiallyVulnerable;
	}
}
