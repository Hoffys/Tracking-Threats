const uniqueStrings = (values, limit = 8) => [...new Set(
  values
    .filter((value) => typeof value === 'string')
    .map((value) => value.trim())
    .filter(Boolean),
)].slice(0, limit)

const providerMatched = (provider) =>
  provider?.checked === true && !provider.error && !provider.skipped && provider.found === true

const humanizeProviderThreat = (value) => {
  const text = String(value ?? '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80)
  return text && !/^malware distribution$/i.test(text) ? text.toLowerCase() : ''
}

const fallbackNames = {
  URL: { dangerous: 'Dangerous website', suspicious: 'Suspicious website' },
  Email: { dangerous: 'Dangerous email', suspicious: 'Suspicious email' },
  Message: { dangerous: 'Dangerous message', suspicious: 'Suspicious message' },
  File: { dangerous: 'Dangerous file', suspicious: 'Suspicious file' },
}

const fallbackTypes = {
  URL: 'Website risk',
  Email: 'Email risk',
  Message: 'Message / social-engineering risk',
  File: 'File risk',
}

function result({ threatName, threatType, confidence, whyDetected, evidenceSources }) {
  return {
    threatName,
    threatType,
    confidence,
    whyDetected: uniqueStrings(whyDetected),
    evidenceSources: uniqueStrings(evidenceSources),
  }
}

export function buildThreatClassification(type, analysis = {}) {
  const details = analysis.details ?? {}
  const categories = Array.isArray(details.categories) ? details.categories : []
  const warningSigns = uniqueStrings(analysis.warningSigns ?? [])
  const categoryWarnings = uniqueStrings((details.categoryWarnings ?? []).map((item) =>
    typeof item === 'string' ? item : item?.label))
  const findings = Array.isArray(details.findings) ? details.findings : []
  const findingCodes = new Set(findings.filter((item) => Number(item?.deduction ?? 0) > 0).map((item) => item.code))
  const providers = Array.isArray(details.threatIntel) ? details.threatIntel : []
  const matchedProviders = providers.filter(providerMatched)
  const providerWarnings = uniqueStrings(matchedProviders.map((provider) => provider.warning))
  const warningText = [...warningSigns, ...providerWarnings].join(' ').toLowerCase()
  const whyDetected = [...providerWarnings, ...warningSigns]
  const evidenceSources = matchedProviders.map((provider) => provider.provider)

  if (analysis.status === 'Safe' && categories.includes('piracy-content')) {
    return result({
      threatName: 'Piracy-related content warning',
      threatType: 'Content and download risk',
      confidence: 'Informational',
      whyDetected: categoryWarnings.length ? categoryWarnings : ['Piracy, torrent, repack, cracked-software, or similar content indicators were found.'],
      evidenceSources: ['Content category rules'],
    })
  }

  if (analysis.status === 'Safe' && categories.includes('gambling-content')) {
    return result({
      threatName: 'Gambling-related content warning',
      threatType: 'Content risk',
      confidence: 'Informational',
      whyDetected: categoryWarnings.length ? categoryWarnings : ['Gambling or betting content indicators were found.'],
      evidenceSources: ['Content category rules'],
    })
  }

  if (analysis.status === 'Safe') {
    return result({
      threatName: 'No threat identified',
      threatType: 'None detected',
      confidence: 'No threat detected',
      whyDetected: [analysis.summary || 'No strong threat indicators were found in the checks that ran.'],
      evidenceSources: providers.filter((provider) => provider?.checked === true && !provider.error && !provider.skipped).map((provider) => provider.provider),
    })
  }

  const phishTank = matchedProviders.find((provider) => provider.provider === 'PhishTank')
  if (phishTank) {
    return result({ threatName: 'Verified phishing page', threatType: 'Phishing / credential theft', confidence: 'High', whyDetected, evidenceSources })
  }

  const safeBrowsing = matchedProviders.find((provider) => provider.provider === 'Google Safe Browsing')
  const safeBrowsingTypes = new Set(safeBrowsing?.threatTypes ?? [])
  if (safeBrowsingTypes.has('SOCIAL_ENGINEERING')) {
    return result({ threatName: 'Known social-engineering page', threatType: 'Phishing / credential theft', confidence: 'High', whyDetected, evidenceSources })
  }
  if (safeBrowsing && [...safeBrowsingTypes].some((value) => value !== 'SOCIAL_ENGINEERING')) {
    const unwanted = safeBrowsingTypes.has('UNWANTED_SOFTWARE') || safeBrowsingTypes.has('POTENTIALLY_HARMFUL_APPLICATION')
    return result({
      threatName: unwanted ? 'Potentially harmful software source' : 'Known malicious website',
      threatType: unwanted ? 'Unwanted or harmful software' : 'Malware distribution',
      confidence: 'High', whyDetected, evidenceSources,
    })
  }

  const urlhausUrl = matchedProviders.find((provider) => provider.provider === 'URLhaus URL')
  if (urlhausUrl) {
    const reportedThreat = humanizeProviderThreat(urlhausUrl.threat)
    return result({
      threatName: reportedThreat ? `URLhaus-listed ${reportedThreat}` : 'URLhaus-listed malware source',
      threatType: 'Malware distribution', confidence: 'High', whyDetected, evidenceSources,
    })
  }

  if (matchedProviders.some((provider) => provider.provider === 'URLhaus Host')) {
    return result({ threatName: 'Known malware-hosting domain', threatType: 'Malware distribution', confidence: 'High', whyDetected, evidenceSources })
  }

  if (matchedProviders.some((provider) => provider.provider === 'MalwareBazaar')) {
    return result({
      threatName: 'Known malware file hash',
      threatType: 'Malware / file reputation', confidence: 'High', whyDetected, evidenceSources,
    })
  }

  const virusTotalFile = matchedProviders.find((provider) => provider.provider === 'VirusTotal File')
  if (virusTotalFile) {
    const malicious = Number(virusTotalFile.stats?.malicious ?? 0) > 0 || Number(virusTotalFile.sandbox?.malicious ?? 0) > 0
    return result({
      threatName: malicious ? 'Malicious file hash' : 'Suspicious file hash',
      threatType: 'Malware / file reputation', confidence: malicious ? 'High' : 'Medium', whyDetected, evidenceSources,
    })
  }

  const virusTotalUrl = matchedProviders.find((provider) => provider.provider === 'VirusTotal')
  if (virusTotalUrl) {
    const malicious = Number(virusTotalUrl.stats?.malicious ?? 0) > 0
    return result({
      threatName: malicious ? 'Malicious URL reputation' : 'Suspicious URL reputation',
      threatType: 'Malware / URL reputation', confidence: malicious ? 'High' : 'Medium', whyDetected, evidenceSources,
    })
  }

  if (findingCodes.has('advance-fee')) {
    evidenceSources.push('Message content rules')
    return result({ threatName: 'Suspected advance-fee scam', threatType: 'Financial fraud / social engineering', confidence: 'Medium', whyDetected, evidenceSources })
  }

  const phishingCodes = ['secret-request', 'secret-entry', 'financial-request', 'account-request-link', 'brand-impersonation', 'sender-brand-claim', 'credential-lure', 'url-userinfo', 'deceptive-userinfo']
  const phishingLanguage = /phish|credential|password|secret|trusted brand|impersonat|login|account action|different host|authentication failed/.test(warningText)
  if (phishingCodes.some((code) => findingCodes.has(code)) || phishingLanguage) {
    const threatNames = {
      URL: 'Suspected credential phishing page',
      Email: 'Suspected phishing email',
      Message: 'Suspected phishing message',
      File: 'Potential phishing document',
    }
    evidenceSources.push(type === 'URL' ? 'URL and page rules' : type === 'File' ? 'File content rules' : `${type} content rules`)
    return result({ threatName: threatNames[type] ?? 'Suspected phishing attempt', threatType: 'Phishing / credential theft', confidence: 'Medium', whyDetected, evidenceSources })
  }

  if (/dmarc|dkim|spf|sender authentication/.test(warningText)) {
    evidenceSources.push('Email authentication checks')
    return result({ threatName: 'Suspicious sender authentication', threatType: 'Email spoofing / authentication risk', confidence: 'Medium', whyDetected, evidenceSources })
  }

  if (type === 'File' || categories.includes('file-risk')) {
    evidenceSources.push('File metadata and content checks')
    return result({
      threatName: analysis.status === 'Dangerous' ? 'Potentially dangerous file' : 'Suspicious file',
      threatType: 'File execution / content risk', confidence: 'Medium', whyDetected, evidenceSources,
    })
  }

  if (matchedProviders.some((provider) => provider.provider === 'AbuseIPDB')) {
    return result({ threatName: 'Reported abusive network host', threatType: 'IP / network reputation', confidence: 'Medium', whyDetected, evidenceSources })
  }

  if (matchedProviders.some((provider) => provider.provider === 'DNS Reputation') || /private or reserved|no public .*dns/.test(warningText)) {
    evidenceSources.push('DNS checks')
    return result({ threatName: 'Suspicious network destination', threatType: 'DNS / network risk', confidence: 'Medium', whyDetected, evidenceSources })
  }

  if (findings.some((item) => Number(item?.deduction ?? 0) > 0)) evidenceSources.push('Local detection rules')
  const names = fallbackNames[type] ?? fallbackNames.URL
  return result({
    threatName: analysis.status === 'Dangerous' ? names.dangerous : names.suspicious,
    threatType: fallbackTypes[type] ?? 'Security risk',
    confidence: 'Medium',
    whyDetected: whyDetected.length ? whyDetected : [analysis.summary || 'The scan found risk indicators.'],
    evidenceSources,
  })
}

export function attachThreatClassification(type, analysis) {
  return {
    ...analysis,
    details: {
      ...(analysis.details ?? {}),
      threatClassification: buildThreatClassification(type, analysis),
    },
  }
}
