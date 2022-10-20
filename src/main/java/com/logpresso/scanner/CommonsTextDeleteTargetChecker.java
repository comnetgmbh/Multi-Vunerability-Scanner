package com.logpresso.scanner;

import java.util.HashSet;
import java.util.Set;

public class CommonsTextDeleteTargetChecker implements DeleteTargetChecker {

	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/commons/text/StringSubstitutor.class";
	private boolean includeLog4j1;
	private Set<String> targets;

	public CommonsTextDeleteTargetChecker() {
		targets = new HashSet<String>();
		targets.add(JNDI_LOOKUP_CLASS_PATH);
	}

	@Override
	public boolean isTarget(String entryPath) {
		if (targets.contains(entryPath))
			return true;

		return false;
	}

}
