import { Router } from 'express'
import { requireClientForScan } from '../middleware/clientAuth.js'
import { validateScanInput } from '../middleware/scanInput.js'
import {
  scanEmailHandler,
  scanFileHandler,
  scanMessageHandler,
  scanUrlHandler,
} from '../controllers/scanController.js'

export const scanRoutes = Router()

scanRoutes.post('/scan/url', requireClientForScan, validateScanInput, scanUrlHandler)
scanRoutes.post('/scan/email', requireClientForScan, validateScanInput, scanEmailHandler)
scanRoutes.post('/scan/message', requireClientForScan, validateScanInput, scanMessageHandler)
scanRoutes.post('/scan/file', requireClientForScan, validateScanInput, scanFileHandler)
