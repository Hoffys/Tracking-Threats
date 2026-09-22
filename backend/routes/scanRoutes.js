import { Router } from 'express'
import { requireClientForScan } from '../middleware/clientAuth.js'
import {
  scanEmailHandler,
  scanFileHandler,
  scanMessageHandler,
  scanUrlHandler,
} from '../controllers/scanController.js'

export const scanRoutes = Router()

scanRoutes.post('/scan/url', requireClientForScan, scanUrlHandler)
scanRoutes.post('/scan/email', requireClientForScan, scanEmailHandler)
scanRoutes.post('/scan/message', requireClientForScan, scanMessageHandler)
scanRoutes.post('/scan/file', requireClientForScan, scanFileHandler)
