export const initialScans = [
  {
    id: 'seed-1',
    type: 'Email',
    target: 'security-alert@paypaI-support.com',
    content: 'Verify your account immediately to prevent suspension.',
    date: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    indicators: ['Requests password or login information', 'Uses urgency or pressure words'],
    recommendation:
      'Do not open the link or attachment. Quarantine the message and report it to security.',
    recommendations: [
      'Do not open the link or attachment.',
      'Quarantine the message and report it to security.',
      'Verify any account or payment request using an official website or phone number.',
    ],
    risk: 'critical',
    score: 46,
    status: 'Dangerous',
    summary: 'Found 3 message warning signs.',
    warningSigns: [
      'Uses urgency or pressure words',
      'Requests password or login information',
      'Uses a suspicious call to action',
    ],
  },
  {
    id: 'seed-2',
    type: 'URL',
    target: 'https://company.example.com/policies',
    content: '',
    date: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    indicators: [],
    recommendation:
      'Proceed with normal caution. Keep sender and link context in mind before sharing sensitive information.',
    recommendations: [
      'Proceed with normal caution.',
      'Keep sender and link context in mind before sharing sensitive information.',
    ],
    risk: 'low',
    score: 100,
    status: 'Safe',
    summary: 'No strong URL phishing indicators were found.',
    warningSigns: [],
  },
]

export const initialAlerts = [
  {
    id: 'alert-1',
    title: 'Dangerous Email detected',
    source: 'security-alert@paypaI-support.com',
    severity: 'critical',
    time: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    status: 'new',
    message: 'Found 3 message warning signs.',
  },
]

export const liveEvents = [
  {
    id: 'evt-1',
    source: 'mail-gateway-01',
    title: 'Credential harvesting link blocked',
    detail: 'Inbound message contained a lookalike login page.',
    severity: 'high',
    time: 'Now',
  },
  {
    id: 'evt-2',
    source: 'dns-filter',
    title: 'Suspicious short URL requested',
    detail: 'A shortened URL redirected to a newly registered domain.',
    severity: 'medium',
    time: '2m ago',
  },
  {
    id: 'evt-3',
    source: 'attachment-sandbox',
    title: 'Macro-enabled attachment isolated',
    detail: 'Attachment asked the user to enable macros before rendering.',
    severity: 'critical',
    time: '7m ago',
  },
  {
    id: 'evt-4',
    source: 'mail-gateway-02',
    title: 'Newsletter allowed',
    detail: 'Sender reputation and content checks were clean.',
    severity: 'low',
    time: '12m ago',
  },
]
