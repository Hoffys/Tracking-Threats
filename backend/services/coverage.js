export function providerCoverage(results, limitations = []) {
  const checkedProviders = results.filter((result) => result.checked === true && !result.error && !result.skipped).length
  return {
    status: results.length === 0 ? 'local-only'
      : checkedProviders === results.length ? 'complete'
        : checkedProviders > 0 ? 'partial' : 'unavailable',
    checkedProviders,
    totalProviders: results.length,
    limitations: [...limitations, ...(checkedProviders < results.length
      ? ['Some reputation checks were unavailable or skipped. No match is not proof of safety.'] : [])],
  }
}

export const localCoverage = (limitation) => providerCoverage([], [limitation])
