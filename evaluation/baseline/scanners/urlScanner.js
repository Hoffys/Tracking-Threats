import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'

const suspiciousTlds = [
  'bar',
  'bet',
  'biz',
  'cam',
  'casino',
  'cc',
  'cf',
  'cfd',
  'click',
  'club',
  'cn',
  'cyou',
  'do',
  'fit',
  'ga',
  'gq',
  'icu',
  'info',
  'lat',
  'link',
  'live',
  'loan',
  'ml',
  'monster',
  'mov',
  'online',
  'quest',
  'rest',
  'ru',
  'sbs',
  'shop',
  'site',
  'space',
  'store',
  'tk',
  'top',
  'website',
  'win',
  'work',
  'xyz',
  'zip',
]
const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
const piracyDomains = [
  'dodi',
  'dodi-repacks',
  'dodi-repacks.site',
  'elamigos',
  'elamigos-games',
  'fitgirl',
  'fitgirl-repacks.site',
  'fitgirlrepacks',
  'game3rb',
  'gamedrive',
  'gog-games',
  'igggames',
  'igg-games',
  'kisskh',
  'kisskh.do',
  'oceanofgames',
  'online-fix',
  'ovagames',
  'repack-games',
  'steamrip',
  'steamunlocked',
  'thepiratebay',
  'thepiratebay.org',
]
const gamblingDomains = [
  '1xbet',
  '22bet',
  '888casino',
  'bet365',
  'bet88',
  'binggo',
  'binggoplus',
  'bingo',
  'bingoplus',
  'bovada',
  'casino',
  'dafabet',
  'ggbet',
  'jackpot',
  'luckyplus',
  'megapari',
  'parimatch',
  'stake',
]
const protectedBrands = [
  'amazon',
  'apple',
  'bdo',
  'bingoplus',
  'bpi',
  'facebook',
  'gcash',
  'google',
  'maya',
  'metrobank',
  'microsoft',
  'netflix',
  'paypal',
  'shopee',
  'unionbank',
]
const substitutions = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', '$': 's' }

const parseUrl = (input) => {
  try {
    return new URL(input.includes('://') ? input : `https://${input}`)
  } catch {
    return null
  }
}

const normalizeLookalikes = (value) =>
  value
    .toLowerCase()
    .split('')
    .map((character) => substitutions[character] ?? character)
    .join('')

const getRegistrableName = (host) => {
  const parts = host.replace(/^www\./, '').split('.')
  return parts.length >= 2 ? parts.at(-2) : parts[0]
}

const distance = (left, right) => {
  const rows = Array.from({ length: left.length + 1 }, (_, row) => [row])
  for (let column = 1; column <= right.length; column += 1) rows[0][column] = column
  for (let row = 1; row <= left.length; row += 1) {
    for (let column = 1; column <= right.length; column += 1) {
      const cost = left[row - 1] === right[column - 1] ? 0 : 1
      rows[row][column] = Math.min(
        rows[row - 1][column] + 1,
        rows[row][column - 1] + 1,
        rows[row - 1][column - 1] + cost,
      )
    }
  }
  return rows[left.length][right.length]
}

  const hasTyposquatting = (host) => {
  const domain = getRegistrableName(host)
  const normalized = normalizeLookalikes(domain)
  const domainTokens = domain.split(/[-_]/).filter((token) => token.length >= 5)
  const normalizedTokens = domainTokens.map(normalizeLookalikes)
  return protectedBrands.some((brand) => {
    if (domain === brand) return false
    return (
      normalized === brand ||
      normalized.includes(brand) ||
      distance(normalized, brand) <= 2 ||
      normalizedTokens.some(
        (token) => token !== brand && Math.abs(token.length - brand.length) <= 1 && distance(token, brand) <= 1,
      )
    )
  })
}

const hasShortRandomLookingName = (name) => {
  if (!/^[a-z0-9]{5,8}$/i.test(name)) return false

  const vowels = name.match(/[aeiou]/gi) ?? []
  return /\d/.test(name) || vowels.length <= 1
}

export function getDomain(target) {
  return parseUrl(target)?.hostname ?? target
}

export function scanUrl(urlInput) {
  const target = urlInput.trim()
  const url = parseUrl(target)
  const host = url?.hostname.toLowerCase() ?? target.toLowerCase()
  const path = url?.pathname.toLowerCase() ?? ''
  const search = url?.search.toLowerCase() ?? ''
  const fullUrlText = `${host}${path}${search}`
  const tld = host.split('.').at(-1)
  const registrableName = getRegistrableName(host)
  const warnings = []

  addWarning(warnings, !url, 'URL format is malformed or incomplete', 18)
  addWarning(warnings, url?.protocol !== 'https:', 'URL does not use HTTPS', 16)
  addWarning(warnings, host.startsWith('xn--'), 'Uses punycode domain that may hide lookalike characters', 24)
  addWarning(warnings, (host.match(/-/g) ?? []).length >= 2, 'Domain uses multiple hyphens often seen in fake sites', 12)
  addWarning(warnings, /\d/.test(registrableName) && /[a-z]/i.test(registrableName), 'Domain mixes letters and numbers', 10)
  addWarning(
    warnings,
    /secure|security|verify|verification|account|accounts|login|signin|support|billing|wallet|claim|reward|promo|bonus|update/.test(
      fullUrlText,
    ),
    'URL contains account, verification, or reward wording often used in phishing',
    18,
  )
  addWarning(
    warnings,
    piracyDomains.includes(host.replace(/^www\./, '')) || piracyDomains.includes(registrableName),
    'Known piracy or torrent site domain',
    55,
  )
  addWarning(
    warnings,
    /torrent|pirate|crack|cracked|keygen|warez|magnet|free-download|fitgirl|dodi|elamigos|gog-games|igg-games|igggames|oceanofgames|ovagames|steamrip|steamunlocked|online-fix|repack|repacks|kisskh|watch-?online|drama|anime|movie|stream/.test(
      fullUrlText,
    ),
    'URL contains piracy, torrent, streaming, or cracked software keywords',
    24,
  )
  addWarning(
    warnings,
    gamblingDomains.some((domain) => host.includes(domain) || registrableName.includes(domain)),
    'Known gambling or betting site domain',
    45,
  )
  addWarning(
    warnings,
    /casino|gambl(e|ing)|betting?|sportsbook|slots?|jackpot|poker|roulette|baccarat|sabong|scatter|bonus|withdraw|deposit|freebet|play-?to-?earn/.test(
      fullUrlText,
    ),
    'URL contains gambling, betting, or cash-out keywords',
    24,
  )
  addWarning(warnings, suspiciousTlds.includes(tld), `Uses suspicious .${tld} top-level domain`, 18)
  addWarning(warnings, /^\d{1,3}(\.\d{1,3}){3}$/.test(host), 'Uses an IP address instead of a domain name', 25)
  addWarning(warnings, shorteners.includes(host.replace(/^www\./, '')), 'Uses a URL shortener', 20)
  addWarning(warnings, hasTyposquatting(host), 'Possible typosquatting of a trusted brand', 25)
  addWarning(warnings, /login|verify|signin|account|password/.test(path), 'URL contains credential or account keywords', 14)
  addWarning(warnings, hasShortRandomLookingName(registrableName), 'Uses a short random-looking domain name', 14)
  addWarning(warnings, path.length > 1 && path.length <= 8, 'Uses a short opaque URL path', 8)

  const score = scoreWarnings(warnings)
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)

  return {
    ...risk,
    score,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} URL warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong URL phishing indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
    recommendations,
    recommendation: recommendations.join(' '),
    details: { domain: host },
  }
}
