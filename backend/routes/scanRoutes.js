import { Router } from 'express'
import {
  scanEmailHandler,
  scanFileHandler,
  scanMessageHandler,
  scanUrlHandler,
} from '../controllers/scanController.js'

export const scanRoutes = Router()

scanRoutes.post('/scan/url', scanUrlHandler)
scanRoutes.post('/scan/email', scanEmailHandler)
scanRoutes.post('/scan/message', scanMessageHandler)
scanRoutes.post('/scan/file', scanFileHandler)
