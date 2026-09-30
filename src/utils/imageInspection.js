const maxImageBytes = 8 * 1024 * 1024
const maxDimension = 2048

export function extractImageIndicators(ocrText = '', qrValues = []) {
  const qr = [...new Set(qrValues.map((value) => String(value).trim()).filter(Boolean))].slice(0, 20)
  const text = [...String(ocrText ?? '')].filter((character) => character.charCodeAt(0) !== 0).join('').trim().slice(0, 20000)
  return {
    qr,
    text,
    scanText: [text && `OCR text:\n${text}`, qr.length && `QR/barcode values:\n${qr.join('\n')}`].filter(Boolean).join('\n\n'),
  }
}

async function imageCanvas(file) {
  const bitmap = await createImageBitmap(file)
  const scale = Math.min(1, maxDimension / Math.max(bitmap.width, bitmap.height))
  const canvas = document.createElement('canvas')
  canvas.width = Math.max(1, Math.round(bitmap.width * scale))
  canvas.height = Math.max(1, Math.round(bitmap.height * scale))
  const context = canvas.getContext('2d', { willReadFrequently: true })
  context.drawImage(bitmap, 0, 0, canvas.width, canvas.height)
  bitmap.close()
  return { canvas, context }
}

async function detectQr(canvas, context) {
  if ('BarcodeDetector' in window) {
    try {
      const supported = await window.BarcodeDetector.getSupportedFormats()
      const formats = supported.filter((format) => ['qr_code', 'data_matrix', 'aztec', 'pdf417'].includes(format))
      if (formats.length > 0) {
        const results = await new window.BarcodeDetector({ formats }).detect(canvas)
        return results.map((item) => item.rawValue).filter(Boolean)
      }
    } catch {
      // Fall back to the bundled QR decoder.
    }
  }
  const { default: jsQR } = await import('jsqr')
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height)
  const result = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: 'attemptBoth' })
  return result?.data ? [result.data] : []
}

async function recognizeText(canvas) {
  const { createWorker } = await import('tesseract.js')
  const worker = await createWorker('eng', 1, {
    workerPath: '/ocr/worker.min.js',
    corePath: '/ocr',
    langPath: '/ocr',
  })
  try {
    const result = await worker.recognize(canvas)
    return result?.data?.text ?? ''
  } finally {
    await worker.terminate()
  }
}

export async function inspectImageFile(file) {
  if (!file?.type?.startsWith('image/')) return { qr: [], text: '', scanText: '' }
  if (file.size > maxImageBytes) throw new Error('Image OCR and QR inspection is limited to 8 MB per image')
  const { canvas, context } = await imageCanvas(file)
  const [qrResult, ocrResult] = await Promise.allSettled([detectQr(canvas, context), recognizeText(canvas)])
  if (qrResult.status === 'rejected' && ocrResult.status === 'rejected') {
    throw new Error('This browser could not inspect text or QR codes in the image')
  }
  return extractImageIndicators(
    ocrResult.status === 'fulfilled' ? ocrResult.value : '',
    qrResult.status === 'fulfilled' ? qrResult.value : [],
  )
}
