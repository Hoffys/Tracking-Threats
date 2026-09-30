// Authored scenarios, never labels inferred from scanner scores.
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const cases = {
  tuning: {
    url: [
      ['legitimate', 'official-google-login', 'https://accounts.google.com/login', 'Expected official account sign-in; login vocabulary alone is not phishing.'],
      ['legitimate', 'official-microsoft-support', 'https://support.microsoft.com/account', 'Expected official support page.'],
      ['legitimate', 'community-bank-information', 'https://cedarbank.test/personal-banking', 'Invented bank publishes ordinary service information.'],
      ['legitimate', 'museum-short-path', 'https://museumarchive.test/art', 'Invented museum uses a short, readable path.'],
      ['legitimate', 'software-streaming-docs', 'https://developerreference.test/streaming-api', 'Invented developer documentation uses streaming vocabulary.'],
      ['phishing', 'paypal-brand-suffix', 'http://paypal-account-verify.test/login', 'Invented attacker-controlled PayPal impersonation solicits credentials.'],
      ['phishing', 'google-digit-lookalike', 'https://go0gle.test/signin', 'Invented Google lookalike credential collection endpoint.'],
      ['phishing', 'amazon-brand-subdomain', 'https://amazon.com.parcelreview.test/verification', 'Invented attacker places a brand in subdomains to misrepresent ownership.'],
      ['phishing', 'ipv4-credential-collector', 'http://192.0.2.41/account/verify', 'Documentation-only IP stands for an attacker credential collector.'],
      ['phishing', 'quiet-credential-landing', 'https://documentpreview.test/shared-document', 'Invented credential collector with neutral URL; malicious intent is scenario ground truth, invisible in URL alone.'],
    ],
    message: [
      ['legitimate', 'anti-phishing-password-advice', 'Never share your bank password or passcode. Contact support using the number on your card.', 'Security education explicitly discourages credential disclosure.'],
      ['legitimate', 'routine-payment-receipt', 'Your payment was received. Your credit card receipt is available in the app.', 'Expected transaction confirmation with no credential request.'],
      ['legitimate', 'urgent-maintenance-notice', 'Urgent maintenance: the office lift is suspended until repairs finish.', 'Physical maintenance urgency is unrelated to account fraud.'],
      ['legitimate', 'lunch-arrangement', 'Lunch is at noon tomorrow. Meet by the library.', 'Ordinary personal scheduling.'],
      ['legitimate', 'library-catalog-link', 'The catalog is available at https://townlibrary.test/catalogue', 'Expected informational link to an invented library.'],
      ['phishing', 'sms-bank-otp-theft', 'Urgent: your bank account is suspended. Reply with your password and passcode immediately.', 'Attacker impersonates a bank and requests secrets by reply.'],
      ['phishing', 'sms-prize-fee-theft', 'Winner! Claim reward now. Send your credit card payment and password to release the prize.', 'Invented prize scam collects money and credentials.'],
      ['phishing', 'sms-gcash-link', 'GCash: verify your wallet at http://gcash-wallet-confirm.test/login now.', 'Invented wallet impersonation links to an attacker credential form.'],
      ['phishing', 'quiet-recovery-code-request', 'Please send me the six digit recovery code you just received.', 'Invented attacker requests an authentication secret without familiar urgency keywords.'],
      ['phishing', 'sms-filipino-reward', 'Maari mo na claim reward ngayon! Ibigay ang password at deposit para sa jackpot.', 'Invented Filipino reward lure requests a password and money.'],
    ],
    email: [
      ['legitimate', 'email-support-ticket', { sender: 'help@orchardhelp.test', subject: 'Support ticket resolved', body: 'Your login issue is resolved. Never send us your password.' }, 'Invented support team closes an expected ticket and warns against secret disclosure.'],
      ['legitimate', 'email-bank-statement', { sender: 'statements@rivercredit.test', subject: 'Monthly bank statement', body: 'Your payment summary is ready. Open your usual bank app to review it.' }, 'Expected statement notification directs the customer to their existing app.'],
      ['legitimate', 'email-team-agenda', { sender: 'team@oakstudio.test', subject: 'Design meeting', body: 'The agenda is attached to our calendar event.' }, 'Routine internal meeting notice.'],
      ['legitimate', 'email-security-training', { sender: 'training@securityschool.test', subject: 'Password safety', body: 'Scammers say urgent or account suspended. Never share login credentials or bank details.' }, 'Training quotes scam language while discouraging disclosure.'],
      ['legitimate', 'email-shipping-update', { sender: 'dispatch@ceramicsupply.test', subject: 'Order dispatched', body: 'Read the shipping schedule at https://ceramicsupply.test/delivery-schedule' }, 'Expected invented merchant shipping information.'],
      ['phishing', 'email-microsoft-revalidation', { sender: 'security@micros0ft.test', subject: 'Urgent password expires', body: 'Confirm your login immediately at http://microsoft-account-check.test/verify' }, 'Invented Microsoft impersonator sends a credential-harvesting link.'],
      ['phishing', 'email-paypal-refund', { sender: 'billing@paypa1.test', subject: 'Bank payment suspended', body: 'Send your credit card and password now at http://paypal-refund-confirm.test/account' }, 'Invented PayPal refund pretext steals card details and credentials.'],
      ['phishing', 'email-executive-wire', { sender: 'director@executiveletters.test', subject: 'Confidential transfer', body: 'Wire the invoice funds to the new beneficiary I provide by reply. Keep this between us.' }, 'Invented executive impersonation diverts funds without an obvious bad link.'],
      ['phishing', 'email-netflix-billing', { sender: 'support@netflix-billing.test', subject: 'Urgent payment failure', body: 'Your password is required at http://netflix-update-wallet.test/login to avoid suspension.' }, 'Invented subscription impersonation asks for credentials.'],
      ['phishing', 'email-fake-helpdesk-reply', { sender: 'help@deskverification.test', subject: 'Mailbox review', body: 'Reply with your passcode and backup codes to retain access.' }, 'Invented helpdesk requests authentication secrets by email.'],
    ],
  },
  'held-out': {
    url: [
      ['legitimate', 'official-apple-identity', 'https://appleid.apple.com/sign-in', 'Expected official Apple identity page.'],
      ['legitimate', 'official-bdo-home', 'https://www.bdo.com.ph/personal', 'Expected official bank information page.'],
      ['legitimate', 'university-account-recovery', 'https://campusidentity.test/account/recovery', 'Invented university has a normal account recovery workflow.'],
      ['legitimate', 'retailer-reward-program', 'https://gardenretailer.test/rewards', 'Invented retailer describes an ordinary loyalty program.'],
      ['legitimate', 'arts-drama-listing', 'https://artsfestival.test/drama-programme', 'Invented legitimate festival uses drama vocabulary.'],
      ['phishing', 'apple-userinfo-deception', 'https://apple.com@identityrestore.test/login', 'Invented attacker uses URL userinfo to display a trusted brand before the real host.'],
      ['phishing', 'facebook-typo', 'https://faceb00k.test/account', 'Invented Facebook lookalike collects credentials.'],
      ['phishing', 'bpi-hyphenated-collector', 'http://bpi-secure-update.test/verify', 'Invented BPI brand impersonation collects credentials.'],
      ['phishing', 'brand-in-query-bait', 'https://sessionrenewal.test/form?brand=shopee', 'Invented brand-themed phishing page on unrelated neutral host.'],
      ['phishing', 'cloud-document-oauth-theft', 'https://collaborationfiles.test/invitation', 'Invented malicious consent flow on a plausible host; URL alone cannot establish intent.'],
    ],
    message: [
      ['legitimate', 'fraud-reporting-guidance', 'Report suspicious login requests to support. Our bank never asks for your password by text.', 'Legitimate fraud reporting guidance contains risky vocabulary in a protective context.'],
      ['legitimate', 'password-manager-reminder', 'Use your password manager to create a unique login for each account.', 'Benign credential hygiene advice.'],
      ['legitimate', 'credit-card-expiry-reminder', 'Your credit card expires this month. Visit your regular branch if you need assistance.', 'Expected card expiry reminder without a link or secret request.'],
      ['legitimate', 'community-award-announcement', 'The science fair winner will collect a prize at the school assembly.', 'Public school award announcement, no payment or credential request.'],
      ['legitimate', 'appointment-portal-link', 'Your appointment time is listed at https://healthappointments.test/appointments', 'Expected invented clinic appointment notice.'],
      ['phishing', 'sms-bdo-freeze', 'BDO bank account suspended. Enter your password immediately at http://bdo-security-alert.test/login', 'Invented bank impersonation and credential theft link.'],
      ['phishing', 'sms-apple-device-lock', 'Apple device locked. Verify login at http://apple-device-restore.test/account now.', 'Invented device lock pretext leads to attacker credential collector.'],
      ['phishing', 'sms-parcel-card-harvest', 'Your parcel is held. Enter your credit card at https://parcelredelivery.test/payment to release it.', 'Invented delivery impersonation steals card details.'],
      ['phishing', 'sms-recruitment-id-theft', 'We selected you for a remote role. Send a photo of your identity document and both sides of your card.', 'Invented recruitment lure collects identity and payment data.'],
      ['phishing', 'sms-mfa-approval-fatigue', 'This is IT. Accept the sign-in approval on your phone so I can finish your setup.', 'Invented helpdesk impersonation tricks a victim into approving attacker authentication.'],
    ],
    email: [
      ['legitimate', 'email-password-reset-requested', { sender: 'identity@learningportal.test', subject: 'Your requested password reset', body: 'You requested this reset. Use https://learningportal.test/reset-password or ignore this email.' }, 'User-requested reset from an invented legitimate portal.'],
      ['legitimate', 'email-credit-union-support', { sender: 'support@harborunion.test', subject: 'Bank support hours', body: 'For login assistance visit the branch. Do not email passwords or credit card details.' }, 'Invented credit union gives safe assistance instructions.'],
      ['legitimate', 'email-research-newsletter', { sender: 'editor@biologyjournal.test', subject: 'Research digest', body: 'This edition discusses river habitats and conservation.' }, 'Ordinary scientific newsletter.'],
      ['legitimate', 'email-theatre-tickets', { sender: 'tickets@citytheatre.test', subject: 'Drama ticket receipt', body: 'Your payment is confirmed. Programme: https://citytheatre.test/drama-programme' }, 'Expected theatre ticket receipt; drama is not piracy.'],
      ['legitimate', 'email-benefits-deposit', { sender: 'hr@meadowworks.test', subject: 'Payroll deposit schedule', body: 'Your bonus deposit is scheduled for Friday. No action is required.' }, 'Expected HR compensation notice.'],
      ['phishing', 'email-apple-invoice', { sender: 'billing@apple-invoice.test', subject: 'Urgent credit card verification', body: 'Your account is suspended. Enter password at http://apple-billing-verify.test/login' }, 'Invented Apple billing impersonator steals credentials and card information.'],
      ['phishing', 'email-shopee-refund-code', { sender: 'refund@shopee-refunds.test', subject: 'Refund processing', body: 'Reply with your passcode so our staff can authorize the refund.' }, 'Invented merchant impersonator requests authentication code by reply.'],
      ['phishing', 'email-facebook-policy-appeal', { sender: 'notice@facebook-review.test', subject: 'Urgent page suspended', body: 'Restore login immediately at http://facebook-policy-appeal.test/verify using your password.' }, 'Invented social-media policy threat leads to a fake credential form.'],
      ['phishing', 'email-vendor-account-switch', { sender: 'accounts@supplierletters.test', subject: 'Revised settlement instructions', body: 'Disregard the old beneficiary. Send all future invoice funds to the account in my next reply.' }, 'Invented vendor impersonation diverts funds using an account-change pretext.'],
      ['phishing', 'email-qr-sso-pretext', { sender: 'access@staffvalidation.test', subject: 'Workspace renewal', body: 'Use the QR code on the enclosed notice and enter your organization password to keep access.' }, 'Invented QR credential theft; there is no attachment analysis in this text-only fixture.'],
    ],
  },
}

const directory = new URL('./fixtures/', import.meta.url)
mkdirSync(directory, { recursive: true })
for (const [split, groups] of Object.entries(cases)) {
  const rows = Object.entries(groups).flatMap(([kind, entries]) => entries.map(([label, scenario, input, rationale], index) => {
    const text = typeof input === 'string' ? input : Object.values(input).join(' ')
    const hosts = [...text.matchAll(/https?:\/\/[^\s]+/g)].map(([url]) => new URL(url).hostname)
    if (kind === 'email') hosts.push(input.sender.split('@')[1])
    return {
      id: `${split === 'tuning' ? 'T' : 'H'}-${kind}-${String(index + 1).padStart(2, '0')}`,
      split, kind, label, scenario,
      domains: [...new Set(hosts)], input,
      provenance: { type: 'synthetic', source: 'Authored evaluation scenario v1', method: 'scenario-author', rationale },
    }
  }))
  writeFileSync(fileURLToPath(new URL(`${split}.jsonl`, directory)), rows.map((row) => JSON.stringify(row)).join('\n') + '\n', { flag: 'wx' })
}
